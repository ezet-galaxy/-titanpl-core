use v8;
use v8::ValueSerializerHelper;
use v8::ValueDeserializerHelper;

struct TitanValueSerializerDelegate;
impl v8::ValueSerializerImpl for TitanValueSerializerDelegate {
    fn throw_data_clone_error<'s>(
        &self,
        scope: &mut v8::HandleScope<'s>,
        message: v8::Local<'s, v8::String>,
    ) {
        let error = v8::Exception::error(scope, message);
        scope.throw_exception(error);
    }
}

struct TitanValueDeserializerDelegate;
impl v8::ValueDeserializerImpl for TitanValueDeserializerDelegate {}

pub fn native_serialize(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut retval: v8::ReturnValue,
) {
    let value = args.get(0);
    let context = scope.get_current_context();
    
    // Create serializer with delegate
    let mut serializer = v8::ValueSerializer::new(scope, Box::new(TitanValueSerializerDelegate));
    serializer.write_header();
    
    // Serialize
    match serializer.write_value(context, value) {
        Some(true) => {
            let raw_bytes = serializer.release();
            
            // Generate Uint8Array
            let len = raw_bytes.len();
            let unique_bs = v8::ArrayBuffer::new_backing_store_from_boxed_slice(raw_bytes.into_boxed_slice());
            let shared_bs = unique_bs.make_shared();
            let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &shared_bs);
            
            if let Some(uint8) = v8::Uint8Array::new(scope, array_buffer, 0, len) {
                retval.set(uint8.into());
            }
        },
        _ => {}
    }
}

pub fn native_deserialize(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut retval: v8::ReturnValue,
) {
    // Input: Uint8Array
    let arg0 = args.get(0);
    if !arg0.is_uint8_array() {
         let msg = v8::String::new(scope, "Expected Uint8Array").unwrap();
         let error = v8::Exception::type_error(scope, msg);
         scope.throw_exception(error);
         return;
    }

    let uint8 = v8::Local::<v8::Uint8Array>::try_from(arg0).unwrap();
    let len = uint8.byte_length();
    
    // Copy bytes to vector for deserializer
    let mut data = vec![0u8; len];
    uint8.copy_contents(&mut data);

    let context = scope.get_current_context();
    let deserializer = v8::ValueDeserializer::new(scope, Box::new(TitanValueDeserializerDelegate), &data);
    
    // Read header
    if let Some(true) = deserializer.read_header(context) {
        // Read value
        if let Some(value) = deserializer.read_value(context) {
            retval.set(value);
        } else {
             // Invalid value format
             let msg = v8::String::new(scope, "Failed to deserialize value").unwrap();
             let error = v8::Exception::error(scope, msg);
             scope.throw_exception(error);
        }
    } else {
        // Invalid header
         let msg = v8::String::new(scope, "Invalid serialization header").unwrap();
         let error = v8::Exception::error(scope, msg);
         scope.throw_exception(error);
    }
}

