mod provider;
mod support;
#[cfg(target_os = "macos")]
mod touch_id;

pub use provider::{KeychainProvider, env_dependencies};
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub use touch_id::{
    TOUCH_ID_HELPER_APPROVAL, delete_touch_id_for_helper, read_touch_id_for_helper,
    validate_touch_id_helper_parent, write_touch_id_for_helper,
};
