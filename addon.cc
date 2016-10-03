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

  Local<Object> input_buffer = info[0]->ToObject();

  if (info.Length() < 4) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!info[1]->IsNumber()) {
    Nan::ThrowError("Second argument should be a number (T)");
    return;
  }

  int t = info[1]->NumberValue();

  if (!info[2]->IsNumber()) {
    Nan::ThrowError("Third argument should be a number (R)");
    return;
  }

  int r = info[2]->NumberValue();

  if (!info[3]->IsNumber()) {
    Nan::ThrowError("Fourth argument should be a number (C)");
    return;
  }

  int c = info[3]->NumberValue();

  char * input = node::Buffer::Data(input_buffer);
  uint32_t input_len = node::Buffer::Length(input_buffer);

  unsigned char output[32];

  LYRA2(output, 32, (unsigned char * )input, input_len, (unsigned char * )input, input_len, t, r, c);

  info.GetReturnValue().Set(
       Nan::NewBuffer((char *)output, 32).ToLocalChecked());

  // output_buffer * = Nan::NewBuffer(output, 32);

  // info.GetReturnValue().Set(t * r * c);
  // info.GetReturnValue().Set(output_buffer);
}

NAN_MODULE_INIT(InitAll) {
  Set(target, New<String>("hash").ToLocalChecked(),
    GetFunction(New<FunctionTemplate>(Hash)).ToLocalChecked());
}

NODE_MODULE(addon, InitAll)
