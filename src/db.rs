use axum::async_trait;

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
}
