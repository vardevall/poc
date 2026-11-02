//! Calls from the engine's thread into the Kotlin object that receives events.

use std::sync::Arc;

use jni::objects::{GlobalRef, JObject, JValue};
use jni::{JNIEnv, JavaVM};

/// The Kotlin `EngineCallbacks` of an engine, callable from any thread.
pub struct Bridge {
    vm: JavaVM,
    target: GlobalRef,
}

impl Bridge {
    /// Holds `callbacks` until the bridge is dropped.
    pub fn new(env: &JNIEnv, callbacks: &JObject) -> jni::errors::Result<Arc<Bridge>> {
        Ok(Arc::new(Bridge {
            vm: env.get_java_vm()?,
            target: env.new_global_ref(callbacks)?,
        }))
    }

    /// Calls `method(String)` of the callbacks with `json`. The calling thread is attached to the
    /// VM for good the first time, as the thread of the engine lives as long as the engine does.
    pub fn deliver(&self, method: &str, json: &str) {
        let attached = match self.vm.get_env() {
            Ok(env) => Ok(env),
            Err(_) => self.vm.attach_current_thread_permanently(),
        };
        let Ok(mut env) = attached else { return };
        let _: jni::errors::Result<()> = env.with_local_frame(4, |env| {
            let text = env.new_string(json)?;
            env.call_method(
                &self.target,
                method,
                "(Ljava/lang/String;)V",
                &[JValue::Object(&text)],
            )?;
            Ok(())
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
    }
}
