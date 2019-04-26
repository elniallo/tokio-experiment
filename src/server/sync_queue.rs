use std::error::Error;

use crate::traits::Exception;

#[derive(Debug)]
pub struct SyncJob {
    guid: String,
    active: bool,
    total_work: f64,
}

pub struct SyncQueue {
    queue: Vec<SyncJob>,
}

impl SyncQueue {
    pub fn new() -> Self {
        Self { queue: Vec::new() }
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
            let mut job = self.queue.remove(matched.1);
            job.total_work = total_work;
            if idx <= matched.1 {
                self.queue.insert(idx, job);
            } else {
                self.queue.insert(idx - 1, job);
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

    pub fn get_sync_permission(&mut self, guid: &str) -> Result<bool, Box<Error>> {
        if let Some(job) = self.queue.get_mut(0) {
            if &job.guid == guid {
                println!("{:?} has the ball", &guid);
                job.active = true;
                return Ok(true);
            } else {
                return Ok(false);
            }
        } else {
            return Err(Box::new(Exception::new("No jobs in queue")));
        }
    }

    pub fn end_sync_operation(&mut self) {
        self.queue.remove(0);
    }

    pub fn clear_job(&mut self, guid: &str) {
        self.queue.retain(|job| &job.guid != guid)
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
        if let Some(job) = sync_queue.queue.first() {
            assert!(!(job.total_work < 1.124));
            assert!(!(job.total_work > 1.124));
        }
    }

    #[test]
    fn it_receives_sync_permission_correctly() {
        let mut sync_queue = SyncQueue::new();
        let mut permission = sync_queue.get_sync_permission("abc");
        assert!(permission.is_err());
        let _ = sync_queue.insert(String::from("abd"), 1.123);
        let _ = sync_queue.insert(String::from("abc"), 1.125);
        permission = sync_queue.get_sync_permission("abc");
        assert!(permission.is_ok());
        assert!(permission.unwrap());
        let no_permission = sync_queue.get_sync_permission("abd");
        assert!(no_permission.is_ok());
        assert!(!no_permission.unwrap());
        sync_queue.end_sync_operation();
        let new_permission = sync_queue.get_sync_permission("abd");
        assert!(new_permission.is_ok());
        assert!(new_permission.unwrap());
    }
}
