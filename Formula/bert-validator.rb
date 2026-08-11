# Homebrew formula for bert.validator
#
# To use this formula directly from this repository:
#   brew tap berttejeda/bert.validator https://github.com/berttejeda/bert.validator.git
#   brew install berttejeda/bert.validator/bert-validator
#
# After pushing a new Git tag, replace the sha256 below with the SHA-256 of the
# source archive for that tag, e.g.:
#   curl -sL https://github.com/berttejeda/bert.validator/archive/refs/tags/v1.2.0.tar.gz | shasum -a 256

class BertValidator < Formula
  desc "YAML-driven script validator"
  homepage "https://github.com/berttejeda/bert.validator"
  url "https://github.com/berttejeda/bert.validator/archive/refs/tags/v1.2.0.tar.gz"
  sha256 "36e98c745eb81e3dbd425d31aa30e4541862048581c8676e2f6ad0ece613e135"
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
