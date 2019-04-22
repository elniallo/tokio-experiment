use crate::traits::Exception;
use futures::future;
use futures::stream::Stream;
use std::error::Error;
use tokio::prelude::*;

const START_HEIGHT: u32 = 600000u32;

/// State Machine for Sync operation
pub struct Sync {
    common_height: Option<u32>,
    local_height: u32,
    height_to_check: u32,
    remote_height: u32,
    active: bool,
    in_flight: bool,
}

impl Sync {
    pub fn new(local_height: u32, remote_height: u32) -> Self {
        Self {
            common_height: None,
            local_height,
            height_to_check: START_HEIGHT,
            remote_height,
            active: false,
            in_flight: false,
        }
    }
    fn reset_sync(&mut self) {
        self.common_height = None;
        self.in_flight = false;
    }

    pub fn get_common_height(&self) -> &Option<u32> {
        &self.common_height
    }

    pub fn set_common_height(&mut self, new_height: u32) {
        self.common_height = Some(new_height);
    }

    pub fn is_syncing(&self) -> bool {
        self.active
    }

    pub fn next_height(&self) -> &u32 {
        &self.height_to_check
    }

    pub fn sync(&mut self) {
        self.reset_sync();
        self.active = true;
    }

    pub fn message_in_flight(&mut self) {
        self.in_flight = true;
    }

    pub fn response_received(&mut self) {
        self.in_flight = false;
    }
}

impl Stream for Sync {
    type Item = u32;
    type Error = Box<Error>;
    fn poll(&mut self) -> Poll<Option<u32>, Self::Error> {
        if self.in_flight {
            return Ok(Async::NotReady);
        }
        if !self.active {
            return Ok(Async::Ready(None));
        }
        Ok(Async::Ready(self.common_height))
    }
}