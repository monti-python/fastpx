use std::{future, io, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::watch,
    time::{Instant, sleep_until},
};

pub async fn relay_bidirectional(
    client: TcpStream,
    upstream: TcpStream,
    idle_timeout: Option<Duration>,
) -> io::Result<(u64, u64)> {
    let (client_reader, client_writer) = client.into_split();
    let (upstream_reader, upstream_writer) = upstream.into_split();
    let (activity_tx, activity_rx) = watch::channel(Instant::now());

    let client_to_upstream = pump(client_reader, upstream_writer, activity_tx.clone());
    let upstream_to_client = pump(upstream_reader, client_writer, activity_tx);
    let transfers = async { tokio::try_join!(client_to_upstream, upstream_to_client) };

    if let Some(timeout) = idle_timeout {
        tokio::select! {
            result = transfers => result,
            () = idle_watchdog(activity_rx, timeout) => {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tunnel idle timeout elapsed",
                ))
            }
        }
    } else {
        tokio::select! {
            result = transfers => result,
            () = future::pending() => unreachable!(),
        }
    }
}

async fn pump(
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    activity: watch::Sender<Instant>,
) -> io::Result<u64> {
    let mut transferred = 0_u64;
    // Keep relay buffers on the heap. Two inline 64 KiB arrays become part of
    // the combined async state machine and can exhaust a Tokio worker stack.
    let mut buffer = vec![0_u8; 64 * 1024];

    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(transferred);
        }

        writer.write_all(&buffer[..read]).await?;
        transferred += read as u64;
        activity.send_replace(Instant::now());
    }
}

async fn idle_watchdog(mut activity: watch::Receiver<Instant>, timeout: Duration) {
    loop {
        let deadline = *activity.borrow_and_update() + timeout;
        tokio::select! {
            () = sleep_until(deadline) => {
                if Instant::now() >= *activity.borrow() + timeout {
                    return;
                }
            }
            changed = activity.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}
