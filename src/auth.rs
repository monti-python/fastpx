use thiserror::Error;

/// An authentication scheme supported by Windows SSPI and HTTP proxies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthScheme {
    Negotiate,
    Ntlm,
}

impl AuthScheme {
    #[must_use]
    pub const fn header_name(self) -> &'static str {
        match self {
            Self::Negotiate => "Negotiate",
            Self::Ntlm => "NTLM",
        }
    }
}

/// A per-upstream-connection security context.
pub trait AuthContext: Send {
    /// Consume an optional proxy challenge and produce the next opaque token.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the native authentication provider rejects
    /// the challenge or cannot create the next token.
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<Vec<u8>, AuthError>;
}

/// Creates a fresh security context for each upstream TCP connection.
pub trait AuthFactory: Send + Sync {
    /// Create a security context for `target_name`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the selected scheme is unavailable or native
    /// credentials cannot be acquired.
    fn create(
        &self,
        scheme: AuthScheme,
        target_name: &str,
    ) -> Result<Box<dyn AuthContext>, AuthError>;
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("native SSPI authentication is only available on Windows")]
    UnsupportedPlatform,
    #[error("SSPI authentication failed: {0}")]
    Native(String),
    #[error("the SSPI context is already complete")]
    ContextComplete,
    #[error("the authentication token is too large")]
    TokenTooLarge,
}

/// The platform's native authentication provider.
#[derive(Debug, Default)]
pub struct NativeAuthFactory;

#[cfg(not(windows))]
impl AuthFactory for NativeAuthFactory {
    fn create(
        &self,
        _scheme: AuthScheme,
        _target_name: &str,
    ) -> Result<Box<dyn AuthContext>, AuthError> {
        Err(AuthError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod windows_sspi {
    use std::{ffi::c_void, ptr};

    use windows::{
        Win32::{
            Foundation::{
                SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED,
            },
            Security::{
                Authentication::Identity::{
                    AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext,
                    FreeContextBuffer, FreeCredentialsHandle, ISC_REQ_ALLOCATE_MEMORY,
                    ISC_REQ_CONNECTION, InitializeSecurityContextW, NEGOSSP_NAME_W, NTLMSP_NAME,
                    SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
                    SecBuffer, SecBufferDesc,
                },
                Credentials::SecHandle,
            },
        },
        core::PCWSTR,
    };

    use super::{AuthContext, AuthError, AuthFactory, AuthScheme, NativeAuthFactory};

    struct SspiContext {
        credentials: SecHandle,
        context: SecHandle,
        has_context: bool,
        complete: bool,
        target_name: Vec<u16>,
    }

    impl SspiContext {
        fn new(scheme: AuthScheme, target_name: &str) -> Result<Self, AuthError> {
            let package = match scheme {
                AuthScheme::Negotiate => NEGOSSP_NAME_W,
                AuthScheme::Ntlm => NTLMSP_NAME,
            };
            let mut credentials = SecHandle::default();

            // SAFETY: All optional pointers are null, `credentials` is a valid
            // out-parameter, and the package constants are static NUL-terminated
            // strings supplied by windows-rs.
            unsafe {
                AcquireCredentialsHandleW(
                    PCWSTR::null(),
                    package,
                    SECPKG_CRED_OUTBOUND,
                    None,
                    None,
                    None,
                    None,
                    ptr::from_mut(&mut credentials),
                    None,
                )
            }
            .map_err(|error| AuthError::Native(error.to_string()))?;

            let mut encoded_target: Vec<u16> = target_name.encode_utf16().collect();
            encoded_target.push(0);

            Ok(Self {
                credentials,
                context: SecHandle::default(),
                has_context: false,
                complete: false,
                target_name: encoded_target,
            })
        }
    }

    impl AuthContext for SspiContext {
        fn step(&mut self, challenge: Option<&[u8]>) -> Result<Vec<u8>, AuthError> {
            if self.complete {
                return Err(AuthError::ContextComplete);
            }

            let mut input_buffer = challenge
                .map(|token| {
                    Ok::<_, AuthError>(SecBuffer {
                        cbBuffer: u32::try_from(token.len())
                            .map_err(|_| AuthError::TokenTooLarge)?,
                        BufferType: SECBUFFER_TOKEN,
                        pvBuffer: token.as_ptr().cast_mut().cast::<c_void>(),
                    })
                })
                .transpose()?;
            let input_desc = input_buffer.as_mut().map(|buffer| SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: ptr::from_mut(buffer),
            });

            let mut output_buffer = SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: ptr::null_mut(),
            };
            let mut output_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: ptr::from_mut(&mut output_buffer),
            };
            let mut attributes = 0_u32;
            let existing_context = self.has_context.then_some(ptr::from_ref(&self.context));

            // SAFETY: Every descriptor points to live stack storage for the
            // duration of the call. SSPI owns the allocated output token because
            // ISC_REQ_ALLOCATE_MEMORY is set; it is copied and freed below.
            let status = unsafe {
                InitializeSecurityContextW(
                    Some(ptr::from_ref(&self.credentials)),
                    existing_context,
                    Some(self.target_name.as_ptr()),
                    ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY,
                    0,
                    SECURITY_NATIVE_DREP,
                    input_desc.as_ref().map(ptr::from_ref),
                    0,
                    Some(ptr::from_mut(&mut self.context)),
                    Some(ptr::from_mut(&mut output_desc)),
                    ptr::from_mut(&mut attributes),
                    None,
                )
            };

            let accepted_status = matches!(
                status,
                SEC_E_OK
                    | SEC_I_CONTINUE_NEEDED
                    | SEC_I_COMPLETE_NEEDED
                    | SEC_I_COMPLETE_AND_CONTINUE
            );
            if accepted_status {
                self.has_context = true;
            }

            let completion_error =
                if matches!(status, SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE) {
                    // SAFETY: SSPI initialized `self.context` and `output_desc` in
                    // the successful call immediately above.
                    unsafe {
                        CompleteAuthToken(ptr::from_ref(&self.context), ptr::from_ref(&output_desc))
                    }
                    .err()
                    .map(|error| AuthError::Native(error.to_string()))
                } else {
                    None
                };

            let token = if output_buffer.pvBuffer.is_null() || output_buffer.cbBuffer == 0 {
                Vec::new()
            } else {
                // SAFETY: SSPI returned a buffer of exactly `cbBuffer` bytes.
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        output_buffer.pvBuffer.cast::<u8>(),
                        output_buffer.cbBuffer as usize,
                    )
                };
                bytes.to_vec()
            };

            if !output_buffer.pvBuffer.is_null() {
                // SAFETY: The buffer was allocated by SSPI because
                // ISC_REQ_ALLOCATE_MEMORY was requested.
                let free_result = unsafe { FreeContextBuffer(output_buffer.pvBuffer) };
                if let Err(error) = free_result {
                    return Err(AuthError::Native(error.to_string()));
                }
            }

            if let Some(error) = completion_error {
                return Err(error);
            }
            if !accepted_status {
                return Err(AuthError::Native(format!(
                    "InitializeSecurityContextW returned {:#010x}",
                    u32::from_ne_bytes(status.0.to_ne_bytes())
                )));
            }

            self.complete = matches!(status, SEC_E_OK | SEC_I_COMPLETE_NEEDED);
            Ok(token)
        }
    }

    impl Drop for SspiContext {
        fn drop(&mut self) {
            if self.has_context {
                // SAFETY: The handle was initialized by SSPI and is owned here.
                let _ = unsafe { DeleteSecurityContext(ptr::from_ref(&self.context)) };
            }
            // SAFETY: The credential handle was acquired in `new` and is owned.
            let _ = unsafe { FreeCredentialsHandle(ptr::from_ref(&self.credentials)) };
        }
    }

    impl AuthFactory for NativeAuthFactory {
        fn create(
            &self,
            scheme: AuthScheme,
            target_name: &str,
        ) -> Result<Box<dyn AuthContext>, AuthError> {
            Ok(Box::new(SspiContext::new(scheme, target_name)?))
        }
    }
}
