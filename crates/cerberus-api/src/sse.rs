//! `GET /v1/requests/{id}/events`: Server-Sent Events built on `AgentApi::wait_access_request`.
//!
//! No guard is held while the stream waits. The first event is the current state. A terminal
//! state, a lock or a server shutdown ends the stream. axum sends the `: keep-alive` comment.

use std::convert::Infallible;
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use cerberus_core::approvals::AccessRequestView as CoreView;
use cerberus_core::{AgentApi, AgentContext, CoreError};
use cerberus_types::{AccessRequestId, AccessRequestStatus, ErrorCode, RequestId};
use futures_util::{Stream, stream};
use tokio::sync::watch;

use crate::convert;
use crate::error::ApiError;

/// Interval of the `: keep-alive` comment.
const HEARTBEAT: Duration = Duration::from_secs(15);
/// Longest single wait on the core. A change wakes the wait at once.
const WAIT: Duration = Duration::from_secs(30);

struct Streaming {
    api: AgentApi,
    ctx: AgentContext,
    id: AccessRequestId,
    request_id: RequestId,
    last: CoreView,
    counter: u64,
    first_sent: bool,
    done: bool,
    shutdown: watch::Receiver<bool>,
}

const fn terminal(status: AccessRequestStatus) -> bool {
    !matches!(status, AccessRequestStatus::Pending)
}

impl Streaming {
    /// The `status` event of the current view. Marks the stream done on a terminal status.
    fn status_event(&mut self) -> Event {
        self.counter += 1;
        self.done = terminal(self.last.status);
        match convert::access_request_view(self.last.clone(), self.request_id)
            .ok()
            .and_then(|view| {
                Event::default()
                    .event("status")
                    .id(self.counter.to_string())
                    .json_data(view)
                    .ok()
            }) {
            Some(event) => event,
            None => {
                let error = ApiError::new(ErrorCode::Internal, self.request_id);
                self.error_event(error)
            }
        }
    }

    fn error_event(&mut self, error: ApiError) -> Event {
        self.done = true;
        Event::default()
            .event("error")
            .json_data(error.body())
            .unwrap_or_else(|_| Event::default().event("error").data("{}"))
    }
}

/// Starts the stream. The caller has already read the first state, so a missing or foreign request
/// is a normal JSON error and never an event.
pub fn stream_events(
    api: AgentApi,
    ctx: AgentContext,
    id: AccessRequestId,
    first: CoreView,
    shutdown: watch::Receiver<bool>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let request_id = ctx.request_id;
    let state = Streaming {
        api,
        ctx,
        id,
        request_id,
        last: first,
        counter: 0,
        first_sent: false,
        done: false,
        shutdown,
    };
    let events = stream::unfold(state, |mut st| async move {
        if st.done {
            return None;
        }
        if !st.first_sent {
            st.first_sent = true;
            let event = st.status_event();
            return Some((Ok(event), st));
        }
        loop {
            let waited = tokio::select! {
                _ = st.shutdown.changed() => return None,
                waited = st.api.wait_access_request(&st.ctx, st.id, WAIT) => waited,
            };
            match waited {
                Ok(view) if view != st.last => {
                    st.last = view;
                    let event = st.status_event();
                    return Some((Ok(event), st));
                }
                Ok(_) => {}
                Err(CoreError::Locked) => {
                    st.last.status = AccessRequestStatus::Cancelled;
                    st.last.lease = None;
                    let event = st.status_event();
                    return Some((Ok(event), st));
                }
                Err(error) => {
                    let event = st.error_event(ApiError::from_core(error, st.request_id));
                    return Some((Ok(event), st));
                }
            }
        }
    });
    Sse::new(events).keep_alive(KeepAlive::new().interval(HEARTBEAT).text("keep-alive"))
}
