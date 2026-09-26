{
  autoconf,
  automake,
  curl,
  icu,
  lib,
  libtool,
  openssl,
  pkg-config,
  python3,
  sqlite,
  stdenv,
  urweb,
}:
stdenv.mkDerivation {
  pname = "urmail";
  version = "1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.intersection (lib.fileset.gitTracked ./.) (
      lib.fileset.unions [
        ./autogen.sh
        ./configure.ac
        ./Makefile.am
        ./config.urp.in
        ./urmail.pc.in
        ./lib.urp
        ./urmail.c
        ./urmail.h
        ./urmail.ur
        ./urmail.urs
        ./urmailFfi.urs
        ./examples
        ./tests
        ./README.md
        ./LICENSE
      ]
    );
  };

  nativeBuildInputs = [
    autoconf
    automake
    libtool
    pkg-config
  ];
  # urweb.h includes ICU's headers, and urweb's package does not pass them
  # on, so icu is named here.
  buildInputs = [
    curl
    icu
    urweb
  ];

  preConfigure = ''
    ./autogen.sh
  '';
  configureFlags = [ "--with-urweb=${urweb}" ];
  # The .urp files link liburmail.a, so that an application carries the
  # library instead of depending on this package at run time; nixpkgs would
  # otherwise configure with --disable-static and not build it.
  dontDisableStatic = true;

  # The tests compile and run an Ur/Web application against a fake SMTP
  # server (python) with a self-signed certificate (openssl); the application
  # keeps its queue in a database (sqlite3).
  doCheck = true;
  nativeCheckInputs = [
    curl
    openssl
    python3
    sqlite
    urweb
  ];

  meta = {
    description = "E-mail sending library for Ur/Web";
    license = lib.licenses.bsd3;
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
