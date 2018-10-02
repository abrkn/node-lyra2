#include <nan.h>

extern "C" {
  #include "lib/Sponge.h"
	#include "lib/Sponge.c"
  #include "lib/Lyra2.h"
  #include "lib/Lyra2.c"
}

using v8::FunctionTemplate;
using v8::Handle;
using v8::Object;
using v8::String;
using v8::Local;
using Nan::GetFunction;
using Nan::New;
using Nan::Set;

NAN_METHOD(Hash) {
  // expect a number as the first argument
  // int points = info[0]->Uint32Value();
  // double est = Estimate(points);
  // Isolate* isolate = info.GetIsolate();

  if (info.Length() < 5) {
    Nan::ThrowError("Wrong number of arguments. Expected 5");
    return;
  }

  Local<Object> password_buffer = info[0]->ToObject();
  Local<Object> salt_buffer = info[1]->ToObject();

  if (!info[2]->IsNumber()) {
    Nan::ThrowError("Argument 3 should be a number (T)");
    return;
  }

  int t = info[2]->NumberValue();

  if (!info[3]->IsNumber()) {
    Nan::ThrowError("Argument 4 should be a number (R)");
    return;
  }

  int r = info[3]->NumberValue();

  if (!info[4]->IsNumber()) {
    Nan::ThrowError("Argument 5 should be a number (C)");
    return;
  }

  int c = info[4]->NumberValue();

  void * password = node::Buffer::Data(password_buffer);
  void * salt = node::Buffer::Data(salt_buffer);

  uint32_t password_len = node::Buffer::Length(password_buffer);
  uint32_t salt_len = node::Buffer::Length(salt_buffer);

  Local<Object> output_buffer = Nan::NewBuffer(32).ToLocalChecked();
  void * output = node::Buffer::Data(output_buffer);

  int result = LYRA2(output, 32, password, password_len, salt, salt_len, t, r, c);

  if (result != 0) {
    Nan::ThrowError("Non-zero return code from LYRA2");
  }

  info.GetReturnValue().Set(output_buffer);
}

NAN_MODULE_INIT(InitAll) {
  Set(target, New<String>("hash").ToLocalChecked(),
    GetFunction(New<FunctionTemplate>(Hash)).ToLocalChecked());
}

NODE_MODULE(addon, InitAll)
