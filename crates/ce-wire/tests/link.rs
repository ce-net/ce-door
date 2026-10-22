//! Link<A> against a real server: Finding -> Live, items handed over, a stream end -> Reconnecting -> Live again with
//! the resumed cursor, and a refusal waiting cannot fix -> Refused (the follow returns).
use ce_wire::{Caller, Client, Link, LinkCfg, LinkState, Server};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod feed {
    ce_wire::api! {
        api Feed = "test.link-feed", version 1;
        types { pub struct From { pub since: u32 } pub struct Row { pub n: u32 } }
        ops { 1 => Ping(()) -> (), needs "feed.read"; }
        streams { 2 => Rows(From) -> stream Row, needs "feed.read"; }
    }
}

#[tokio::test]
async fn follows_reconnects_resumes_then_stops_on_refusal() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    // Hello 1 and 2 are accepted, the third is refused: the right is gone (revoked), so waiting cannot help.
    let hellos = Arc::new(AtomicU32::new(0));
    let h2 = hellos.clone();
    let s = Server::<feed::Feed>::new(move |_| {
        if h2.fetch_add(1, Ordering::SeqCst) < 2 {
            Ok(Caller { name: "t".into(), rights: vec!["feed.read".into()] })
        } else {
            Ok(Caller { name: "t".into(), rights: vec![] })
        }
    })
    .on::<feed::Ping, _, _>(|_: (), _| async move { Ok(()) })
    .stream::<feed::Rows, _, _>(|f: feed::From, _, sink| async move {
        // two rows after the cursor, then a normal end (the link must reconnect)
        for n in f.since + 1..=f.since + 2 {
            sink.send(&feed::Row { n }).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    tokio::spawn(s.serve(l));

    let link = Link::<feed::Feed>::new(move || Client::<feed::Feed>::connect(a, vec![]))
        .with(LinkCfg { first_wait: Duration::from_millis(20), max_wait: Duration::from_millis(40), max_attempts: 0, stale_after: Duration::from_secs(5) });
    let mut states = link.states();
    let seen = Arc::new(std::sync::Mutex::new(vec![]));
    let (s2, mut since) = (seen.clone(), 0u32);
    let log = tokio::spawn(async move {
        let mut v = vec![];
        while states.changed().await.is_ok() {
            v.push(states.borrow().clone());
        }
        v
    });
    let end = tokio::time::timeout(
        Duration::from_secs(10),
        link.follow::<feed::Rows, _, _>(
            || feed::From { since: s2.lock().unwrap().last().copied().unwrap_or(0) },
            |r| {
                since = r.n;
                seen.lock().unwrap().push(r.n);
            },
        ),
    )
    .await
    .expect("follow returns on the refusal");
    assert!(matches!(&end, LinkState::Refused { why } if why.contains("feed.read")), "{end:?}");
    assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3, 4], "the second connect resumed after row 2");
    assert_eq!(since, 4);
    drop(link);
    let v = log.await.unwrap();
    let names: Vec<&str> = v.iter().map(|s| match s { LinkState::Finding => "finding", LinkState::Live { .. } => "live", LinkState::Reconnecting { .. } => "reconnecting", LinkState::Refused { .. } => "refused", _ => "other" }).collect();
    assert_eq!(names.first(), Some(&"finding"));
    assert!(names.windows(2).any(|w| w == ["reconnecting", "finding"]), "{names:?}");
    assert_eq!(names.last(), Some(&"refused"));
}
