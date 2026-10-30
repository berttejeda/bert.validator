# Homebrew formula for bert.validator
#
# To use this formula directly from this repository:
#   brew tap berttejeda/bert.validator https://github.com/berttejeda/bert.validator.git
#   brew install berttejeda/bert.validator/bert-validator
#
# After pushing a new Git tag, replace the sha256 below with the SHA-256 of the
# source archive for that tag, e.g.:
#   curl -sL https://github.com/berttejeda/bert.validator/archive/refs/tags/v1.7.1.tar.gz | shasum -a 256

class BertValidator < Formula
  desc "YAML-driven script validator"
  homepage "https://github.com/berttejeda/bert.validator"
  url "https://github.com/berttejeda/bert.validator/archive/refs/tags/v1.9.1.tar.gz"
  sha256 "c6f744337a5f6db2210812142ed60c2be564ed2e166f0fdbc3967d7e29ab3c9c"
  license "MIT"
  head "https://github.com/berttejeda/bert.validator.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", "-trimpath",
           "-ldflags", "-s -w -X main.Version=#{version}",
           "-o", bin/"validator"
  end

  test do
    system bin/"validator", "--version"
  end
end
