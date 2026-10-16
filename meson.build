project('cosmic', 'c',
  license: 'MIT',
  version: '0.1',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=release'])

add_project_arguments('-Wno-unused-parameter', language: 'c')

executable('cosmic',
  'src/main.c', 'src/paths.c', 'src/manifest.c', 'src/keys.c', 'src/read.c',
  'src/write.c', 'src/install.c',
  dependencies: [
    dependency('libcrypto'),
    dependency('libarchive'),
    dependency('json-c'),
  ],
  install: true)
