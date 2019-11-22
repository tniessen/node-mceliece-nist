{
  "targets": [
    {
      "target_name": "node_mceliece",
      "sources": ["node_mceliece.cc"],
      "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")", "<(module_root_dir)/deps/mceliece"],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")", "<(module_root_dir)/deps/mceliece/binding.gyp:mceliece"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
    }
  ]
}
