"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { parseManifest, matchStack, stackFromMatch, normName, MATCH_ALIASES } = require("../js/stack.js");

const ECO = [
  { id: "npm", label: "npm", packages: [
    { key: "npm/react", name: "react", label: "React" },
    { key: "npm/@angular/core", name: "@angular/core", label: "Angular" },
    { key: "npm/lodash", name: "lodash", label: "lodash" },
    { key: "npm/express", name: "express", label: "Express" },
    { key: "npm/undici", name: "undici", label: "undici" },
  ]},
  { id: "pypi", label: "PyPI", packages: [
    { key: "pypi/django", name: "django", label: "Django" },
    { key: "pypi/pillow", name: "pillow", label: "pillow" },
    { key: "pypi/pyyaml", name: "pyyaml", label: "pyyaml" },
    { key: "pypi/requests", name: "requests", label: "requests" },
    { key: "pypi/python-dateutil", name: "python-dateutil", label: "python-dateutil" },
  ]},
  { id: "maven", label: "Maven", packages: [
    { key: "maven/org.springframework.boot:spring-boot", name: "org.springframework.boot:spring-boot", label: "Spring Boot" },
    { key: "maven/com.google.guava:guava", name: "com.google.guava:guava", label: "guava" },
    { key: "maven/org.apache.logging.log4j:log4j-core", name: "org.apache.logging.log4j:log4j-core", label: "log4j-core" },
  ]},
  { id: "nuget", label: "NuGet", packages: [
    { key: "nuget/Microsoft.AspNetCore.App.Runtime.linux-x64", name: "Microsoft.AspNetCore.App.Runtime.linux-x64", label: "ASP.NET Core" },
    { key: "nuget/Microsoft.AspNetCore.Components", name: "Microsoft.AspNetCore.Components", label: "Blazor" },
    { key: "nuget/Newtonsoft.Json", name: "Newtonsoft.Json", label: "Newtonsoft.Json" },
    { key: "nuget/System.IdentityModel.Tokens.Jwt", name: "System.IdentityModel.Tokens.Jwt", label: "IdentityModel JWT" },
  ]},
  { id: "crates", label: "crates.io", packages: [
    { key: "crates/tokio", name: "tokio", label: "tokio" },
    { key: "crates/serde_json", name: "serde_json", label: "serde_json" },
    { key: "crates/rustls", name: "rustls", label: "rustls" },
  ]},
  { id: "packagist", label: "Packagist", packages: [
    { key: "packagist/laravel/framework", name: "laravel/framework", label: "Laravel" },
    { key: "packagist/symfony/http-kernel", name: "symfony/http-kernel", label: "Symfony" },
    { key: "packagist/drupal/core", name: "drupal/core", label: "Drupal core" },
  ]},
  { id: "go", label: "Go", packages: [
    { key: "go/github.com/gin-gonic/gin", name: "github.com/gin-gonic/gin", label: "Gin" },
    { key: "go/golang.org/x/net", name: "golang.org/x/net", label: "x/net" },
    { key: "go/github.com/docker/docker", name: "github.com/docker/docker", label: "Docker (moby)" },
    { key: "go/github.com/labstack/echo/v4", name: "github.com/labstack/echo/v4", label: "Echo" },
  ]},
  { id: "rubygems", label: "RubyGems", packages: [
    { key: "rubygems/rails", name: "rails", label: "Ruby on Rails" },
    { key: "rubygems/nokogiri", name: "nokogiri", label: "nokogiri" },
  ]},
  { id: "hex", label: "Hex", packages: [
    { key: "hex/phoenix", name: "phoenix", label: "Phoenix" },
    { key: "hex/cowboy", name: "cowboy", label: "cowboy" },
  ]},
  { id: "runtimes", label: "Runtimes & servers", packages: [
    { key: "runtimes/python", name: "python", label: "Python" },
    { key: "runtimes/node", name: "node", label: "Node.js" },
  ]},
];

function keys(result) { return result.tracked.map((t) => t.key); }
function untracked(result) { return result.untracked.map((u) => `${u.eco}:${u.name}`); }

test("PyPI normalization collapses case, underscore, dot and hyphen", () => {
  assert.equal(normName("pypi", "Pillow"), "pillow");
  assert.equal(normName("pypi", "PyYAML"), "pyyaml");
  assert.equal(normName("pypi", "python_dateutil"), "python-dateutil");
  assert.equal(normName("pypi", "Zope.Interface"), "zope-interface");
  assert.equal(normName("pypi", "foo--bar"), "foo-bar");
  assert.equal(normName("npm", "@Angular/Core"), "@angular/core");
  assert.equal(normName("nuget", "Newtonsoft.Json"), "newtonsoft.json");
  assert.equal(normName("go", "github.com/Gin-Gonic/gin"), "github.com/Gin-Gonic/gin");
});

test("package.json dependencies, scopes, and direct lockfile deps", () => {
  const parsed = parseManifest(`{
    "name": "demo",
    "dependencies": { "react": "^18.2.0", "@angular/core": "^18.0.0", "left-pad": "1.3.0" },
    "devDependencies": { "lodash": "^4.17.21" },
    "peerDependencies": { "Express": "^4.0.0" },
    "scripts": { "test": "vitest" }
  }`);
  assert.equal(parsed.format, "npm");
  assert.equal(parsed.error, null);
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), ["npm/react", "npm/@angular/core", "npm/lodash", "npm/express"]);
  assert.deepEqual(untracked(matched), ["npm:left-pad"]);

  const lock = parseManifest(JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { react: "^18.0.0", undici: "^6.0.0" } },
      "node_modules/left-pad": { version: "1.3.0" },
      "node_modules/react": { version: "18.3.1" },
    },
  }));
  assert.equal(lock.format, "npm");
  assert.deepEqual(lock.packages, ["react", "undici"]);
});

test("requirements.txt versions, extras, markers, edits and normalization", () => {
  const parsed = parseManifest(`
# app
Django>=4.2
Pillow[webp]==10.4.0
PyYAML~=6.0
python_dateutil>=2.8 ; python_version >= "3.8"
requests @ https://example.com/requests.tgz
-e git+https://example.com/private.git@v1#egg=private-lib
-r base.txt
--index-url https://pypi.org/simple
./local
express==1.0.0
`);
  assert.equal(parsed.format, "pypi");
  assert.deepEqual(parsed.packages, ["Django", "Pillow", "PyYAML", "python_dateutil", "requests", "private-lib", "express"]);
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), ["pypi/django", "pypi/pillow", "pypi/pyyaml", "pypi/python-dateutil", "pypi/requests"]);
  assert.deepEqual(untracked(matched), ["pypi:private-lib", "pypi:express"]);
});

test("requirements continued lines and inline comments", () => {
  const parsed = parseManifest("requests==2.31.0 \\\n  --hash=sha256:abc\n# comment\nurllib3>=2  # pin\n");
  assert.equal(parsed.format, "pypi");
  assert.deepEqual(parsed.packages, ["requests", "urllib3"]);
});

test("pyproject.toml poetry and PEP 621", () => {
  const poetry = parseManifest(`
[tool.poetry.dependencies]
python = "^3.11"
django = "^4.2"
Pillow = "^10.0"

[tool.poetry.group.dev.dependencies]
pytest = "^8"
`);
  assert.equal(poetry.format, "pypi");
  assert.deepEqual(poetry.packages, ["django", "Pillow", "pytest"]);

  const pep = parseManifest(`
[project]
name = "demo"
dependencies = [
  "PyYAML>=6",
  "python-dateutil>=2.8",
]
[project.optional-dependencies]
dev = ["requests>=2"]
`);
  assert.equal(pep.format, "pypi");
  assert.deepEqual(pep.packages, ["PyYAML", "python-dateutil", "requests"]);
});

test("Pipfile", () => {
  const parsed = parseManifest(`
[[source]]
url = "https://pypi.org/simple"
[packages]
flask = "*"
"PyYAML" = "*"
[dev-packages]
pytest = "*"
`);
  assert.equal(parsed.format, "pypi");
  assert.deepEqual(parsed.packages, ["flask", "PyYAML", "pytest"]);
});

test("go.mod require block, single require, and docker alias", () => {
  const parsed = parseManifest(`
module example.com/app

go 1.22

require (
  github.com/gin-gonic/gin v1.9.1
  golang.org/x/net v0.20.0 // indirect
  github.com/someone/private v0.1.0
)

require github.com/moby/moby v0.1.0
`);
  assert.equal(parsed.format, "gomod");
  assert.equal(parsed.eco, "go");
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), ["go/github.com/gin-gonic/gin", "go/golang.org/x/net", "go/github.com/docker/docker"]);
  assert.deepEqual(untracked(matched), ["go:github.com/someone/private"]);
  const echo = matchStack(parseManifest("module x\n\ngo 1.22\n\nrequire github.com/labstack/echo/v4 v4.12.0\n"), ECO);
  assert.deepEqual(keys(echo), ["go/github.com/labstack/echo/v4"]);
});

test("Cargo.toml tables, renames, and rustls alias", () => {
  const parsed = parseManifest(`
[package]
name = "app"
version = "0.1.0"

[dependencies]
tokio = { version = "1", features = ["full"] }
serde_json = "1"
cool = { package = "rustls", version = "0.23" }
rustls-webpki = "0.102"

[dev-dependencies]
tempfile = "3"

[dependencies.regex]
version = "1"
`);
  assert.equal(parsed.format, "cargo");
  assert.deepEqual(parsed.packages, ["tokio", "serde_json", "rustls", "rustls-webpki", "tempfile", "regex"]);
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), ["crates/tokio", "crates/serde_json", "crates/rustls"]);
  assert.ok(matched.tracked.find((t) => t.key === "crates/rustls").via.includes("rustls-webpki"));
  assert.deepEqual(untracked(matched), ["crates:tempfile", "crates:regex"]);
});

test("pom.xml coordinates and Spring Boot prefix, ignoring plugins", () => {
  const parsed = parseManifest(`
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>internal</artifactId>
    </dependency>
  </dependencies>
  <build><plugins>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-compiler-plugin</artifactId>
    </plugin>
  </plugins></build>
</project>`);
  assert.equal(parsed.format, "maven");
  assert.deepEqual(parsed.packages, [
    "org.springframework.boot:spring-boot-starter-web",
    "com.google.guava:guava",
    "com.example:internal",
  ]);
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), ["maven/org.springframework.boot:spring-boot", "maven/com.google.guava:guava"]);
  assert.deepEqual(matched.tracked[0].via, ["org.springframework.boot:spring-boot-starter-web"]);
  assert.deepEqual(untracked(matched), ["maven:com.example:internal"]);
});

test("Gemfile rails components collapse onto the Rails tile", () => {
  const parsed = parseManifest(`
source "https://rubygems.org"
gem "rails", "~> 7.1"
gem 'actionpack'
gem "nokogiri"
# gem "ignored"
gem "private_gem", group: :development
`);
  assert.equal(parsed.format, "gem");
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), ["rubygems/rails", "rubygems/nokogiri"]);
  assert.deepEqual(matched.tracked[0].via, ["rails", "actionpack"]);
  assert.deepEqual(untracked(matched), ["rubygems:private_gem"]);
});

test("composer.json skips php and extensions; symfony prefix and drupal alias", () => {
  const parsed = parseManifest(JSON.stringify({
    require: {
      php: "^8.2",
      "ext-json": "*",
      "laravel/framework": "^10",
      "symfony/console": "^6",
      "drupal/drupal": "^10",
    },
    "require-dev": { "phpunit/phpunit": "^10", "my/private": "^1" },
  }));
  assert.equal(parsed.format, "composer");
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), ["packagist/laravel/framework", "packagist/symfony/http-kernel", "packagist/drupal/core"]);
  assert.deepEqual(untracked(matched), ["packagist:phpunit/phpunit", "packagist:my/private"]);
});

test("NuGet PackageReference is case-insensitive and the longest prefix wins", () => {
  const parsed = parseManifest(`
<Project>
  <ItemGroup>
    <PackageReference Include="newtonsoft.json" Version="13.0.3" />
    <PackageReference Include="Microsoft.AspNetCore.Mvc" Version="8.0.0" />
    <PackageReference Include="Microsoft.AspNetCore.Components.Web" Version="8.0.0" />
    <PackageReference Include="Microsoft.IdentityModel.Tokens" Version="7.0.0" />
    <PackageReference Include="Humanizer" Version="2.14.1" />
  </ItemGroup>
</Project>`);
  assert.equal(parsed.format, "nuget");
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), [
    "nuget/Newtonsoft.Json",
    "nuget/Microsoft.AspNetCore.App.Runtime.linux-x64",
    "nuget/Microsoft.AspNetCore.Components",
    "nuget/System.IdentityModel.Tokens.Jwt",
  ]);
  assert.deepEqual(untracked(matched), ["nuget:Humanizer"]);
});

test("mix.exs deps only, cowboy alias", () => {
  const parsed = parseManifest(`
defmodule App.MixProject do
  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:cowlib, "~> 2.12"},
      {:jason, "~> 1.4"}
    ]
  end
  def read do
    {:ok, body}
  end
end
`);
  assert.equal(parsed.format, "mix");
  const matched = matchStack(parsed, ECO);
  assert.deepEqual(keys(matched), ["hex/phoenix", "hex/cowboy"]);
  assert.deepEqual(untracked(matched), ["hex:jason"]);
});

test("a requirements name does not match the same string in another ecosystem", () => {
  const matched = matchStack(parseManifest("express==1.0\npython==1.0\n"), ECO);
  assert.deepEqual(keys(matched), []);
  assert.deepEqual(untracked(matched), ["pypi:express", "pypi:python"]);
});

test("data match field overrides and unions with the built-in table", () => {
  const ecos = [{ id: "npm", label: "npm", packages: [
    { key: "npm/react", name: "react", label: "React", match: ["react-dom"] },
  ]}];
  const matched = matchStack(parseManifest('{ "dependencies": { "react-dom": "18.0.0" } }'), ecos);
  assert.deepEqual(keys(matched), ["npm/react"]);
});

test("unrecognized text and broken JSON do not invent packages", () => {
  assert.equal(parseManifest("hello, this is a note about dependencies").error, "format");
  assert.equal(parseManifest("{ not json").error, "json");
  assert.equal(parseManifest("").error, "empty");
  assert.equal(parseManifest("   \n").error, "empty");
  assert.equal(parseManifest("{").error, "json");
  const huge = "a".repeat(1000001);
  assert.equal(parseManifest(huge).error, "large");
});

test("adding a manifest unions tracked packages and keeps untracked names", () => {
  const npm = matchStack(parseManifest('{ "dependencies": { "react": "18", "left-pad": "1" } }'), ECO);
  const py = matchStack(parseManifest("Django>=4\nprivatepkg==1\n"), ECO);
  const first = stackFromMatch(npm, null, "replace");
  const both = stackFromMatch(py, first, "add");
  assert.deepEqual(both.tracked, ["npm/react", "pypi/django"]);
  assert.deepEqual(both.untracked, [
    { eco: "npm", name: "left-pad" },
    { eco: "pypi", name: "privatepkg" },
  ]);
  const again = stackFromMatch(npm, both, "add");
  assert.deepEqual(again.tracked, ["npm/react", "pypi/django"]);
  assert.equal(again.untracked.length, 2);
  const replaced = stackFromMatch(py, both, "replace");
  assert.deepEqual(replaced.tracked, ["pypi/django"]);
  assert.deepEqual(replaced.untracked, [{ eco: "pypi", name: "privatepkg" }]);
});

function aliasesFromStacks(src) {
  const body = src.split(/^ecosystems:\s*$/m)[1] || "";
  const out = {};
  let eco = null;
  let name = null;
  for (const raw of body.split("\n")) {
    const line = raw.replace(/^\s*#.*/, "").replace(/\s+#.*$/, "");
    const idM = line.match(/^\s*- id:\s*([A-Za-z0-9_]+)\s*$/);
    if (idM) { eco = idM[1]; name = null; continue; }
    const nameM = line.match(/name:\s*("?)([^",}\s]+)\1/);
    if (nameM) name = nameM[2];
    const matchM = line.match(/match:\s*\[([^\]]*)\]/);
    if (matchM && eco && name) {
      out[`${eco}/${name}`] = matchM[1].split(",").map((s) => s.trim().replace(/^["']|["']$/g, "")).filter(Boolean);
    }
  }
  return out;
}

test("built-in match aliases stay in sync with collect/stacks.yml", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "collect", "stacks.yml"), "utf8");
  assert.deepEqual(aliasesFromStacks(src), MATCH_ALIASES);
});
