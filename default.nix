{ lib
, stdenv
, iana-etc
, libredirect
, python311
, fetchFromGitHub
}:

python311.pkgs.buildPythonApplication rec {
  pname = "py-profinet";
  version = "unstable-2023-11-27";
  pyproject = true;

  src = ./.;

  nativeBuildInputs = [
    python311.pkgs.flit-core
  ];

  propagatedBuildInputs = with python311.pkgs; [
    aiohttp-retry
    aiomqtt
    async-timeout
    influxdb-client
    pint
    pyyaml
    scapy
    structlog
  ];

  pythonImportsCheck = [ "pnio.controller" ];

  # https://nixos.wiki/wiki/Packaging/Quirks_and_Caveats#Test_cannot_access_.2Fetc.2Fprotocols.2C_.2Fetc.2Fservices_or_expects_a_special_.2Fetc.2Fpasswd_when_building_in_sandbox
  preInstallCheck = lib.optionalString stdenv.isLinux ''
    export NIX_REDIRECTS=/etc/services=${iana-etc}/etc/services \
      LD_PRELOAD=${libredirect}/lib/libredirect.so
  '';
  exitHook = lib.optionalString stdenv.isLinux ''
    unset NIX_REDIRECTS LD_PRELOAD
  '';

  meta = with lib; {
    description = "This repository aims to simulate a Profinet-Controller. Based on a GSDML file the connection is established and cyclic messages are exchanged";
    homepage = "https://github.com/quentinmit/py-profinet";
    license = licenses.gpl2;
    maintainers = with maintainers; [ quentin ];
    mainProgram = "py-profinet";
  };
}
