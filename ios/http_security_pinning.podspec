#
# Run `pod lib lint http_security_pinning.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'http_security_pinning'
  s.version          = '2.0.0'
  s.summary          = 'TLS certificate pinning against SPKI SHA-256 hashes for Flutter.'
  s.description      = <<-DESC
Reads the certificate chain presented during the TLS handshake so that the
Dart client can pin the connection to SPKI SHA-256 hashes.
                       DESC
  s.homepage         = 'https://github.com/CaoGiaHieu-dev/http_security_pinning'
  s.license          = { :type => 'BSD-3-Clause', :file => '../LICENSE' }
  s.author           = { 'Cao Gia Hieu' => 'caogiahieu99@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files = 'http_security_pinning/Sources/http_security_pinning/**/*.{h,m}'
  s.public_header_files = 'http_security_pinning/Sources/http_security_pinning/include/**/*.h'
  s.dependency 'Flutter'
  s.frameworks = 'Security'
  s.platform = :ios, '13.0'
  s.resource_bundles = {
    'http_security_pinning_privacy' => ['http_security_pinning/Sources/http_security_pinning/PrivacyInfo.xcprivacy']
  }

  # Flutter.framework does not contain an i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
end
