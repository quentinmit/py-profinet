{ lib
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

  meta = with lib; {
    description = "This repository aims to simulate a Profinet-Controller. Based on a GSDML file the connection is established and cyclic messages are exchanged";
    homepage = "https://github.com/quentinmit/py-profinet";
    license = licenses.gpl2;
    maintainers = with maintainers; [ quentin ];
    mainProgram = "py-profinet";
  };
}
