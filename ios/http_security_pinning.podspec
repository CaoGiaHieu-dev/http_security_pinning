Pod::Spec.new do |s|
  s.name             = 'http_security_pinning'
  s.version          = '1.0.0'
  s.summary          = 'A Flutter plugin for certificate pinning with HTTP security.'
  s.description      = <<-DESC
A Flutter plugin that uses certificate pinning via SPKI hashes.
                       DESC
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = { 'Cao Gia Hieu' => 'caogiahieu99@gmail.com' }
  s.source           = { :path => '.' }
  s.homepage         = 'https://github.com/CaoGiaHieu-dev/http_security_pinning.git'
  s.source_files = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.dependency 'Flutter'
  s.platform = :ios, '10.0'
  # Flutter.framework does not contain an i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
end
