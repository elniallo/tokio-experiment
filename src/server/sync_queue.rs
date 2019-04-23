use std::collections::VecDeque;
use std::error::Error;

use crate::traits::Exception;

pub struct SyncJob {
    guid: String,
    active: bool,
    total_work: f64,
}

pub struct SyncQueue {
    queue: VecDeque<SyncJob>,
}

impl SyncQueue {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
    /// Inserts or updates an entry corresponding to the given GUID
    pub fn insert(&mut self, guid: String, total_work: f64) -> Result<(), Box<Error>> {
        let mut insert_index = None;
        let mut matched = (false, 0);
        let mut queue_iter = self.queue.iter().enumerate();
        while let Some((index, job)) = queue_iter.next() {
            if total_work > job.total_work && insert_index.is_none() && !job.active {
                insert_index = Some(index);
                if matched.0 {
                    break;
                }
            }
            if job.guid == guid {
                if job.active {
                    return Err(Box::new(Exception::new("Already syncing with this peer")));
                }
                matched = (true, index);
                if insert_index.is_some() {
                    break;
                }
            }
        }
        let idx;
        if let Some(num) = insert_index {
            idx = num;
        } else {
            idx = self.queue.len()
        }
        if matched.0 {
            if let Some(mut job) = self.queue.remove(matched.1) {
                job.total_work = total_work;
                self.queue.insert(idx, job);
            } else {
                return Err(Box::new(Exception::new("Error updating job")));
            }
        } else {
            let sync_job = SyncJob {
                guid,
                active: false,
                total_work,
            };
            self.queue.insert(idx, sync_job);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_inserts_into_the_queue_correctly_based_on_total_work() {
        let mut sync_queue = SyncQueue::new();
        let _ = sync_queue.insert(String::from("abc"), 1.123);
        assert!(sync_queue.queue.len() == 1);
        let _ = sync_queue.insert(String::from("abc"), 1.124);
        if let Some(job) = sync_queue.queue.pop_front() {
            assert!(!(job.total_work < 1.124));
            assert!(!(job.total_work > 1.124));
        }
    }
}
