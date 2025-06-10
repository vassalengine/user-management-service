use async_trait::async_trait;

use crate::{
    core::CoreError,
    model::UserUpdateParams
};

#[async_trait]
pub trait DatabaseClient {
    async fn get_user_avatar_template(
        &self,
        _username: &str
    ) -> Result<String, CoreError>
    {
        unimplemented!();
    }

    async fn update_user(
        &self,
        _params: &UserUpdateParams
    ) -> Result<(), CoreError>
    {
        unimplemented!();
    }

    async fn create_session(
        &self,
        _uid: i64,
        _session_id: &str,
        _expires: i64
    ) -> Result<(), CoreError>
    {
        unimplemented!();
    }

    async fn verify_session(
        &self,
        _session_id: &str,
        _now: i64
    ) -> Result<Option<i64>, CoreError>
    {
        unimplemented!();
    }

    async fn delete_session(
        &self,
        _session_id: &str,
    ) -> Result<(), CoreError>
    {
        unimplemented!();
    }
}
