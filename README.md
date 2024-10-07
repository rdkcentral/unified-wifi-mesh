Introduction
Unified-Wifi-Mesh is an end-to-end Wi-Fi mesh stack that facilitates configuration of parameters of Wi-Fi mesh network along with retrieval of different statistics and telemetry of different components of the network including devices, radios, Access Points, Client devices and neighbors. The stack is compatible with EasyMesh and WiFi-7 specifications. Currently, the implementation is compliant with Wi-Fi Alliance published Wi-Fi EasyMesh Specifications Version 5.0. An upgrade to Version 6.0 is planned by middle of 2025.

Building Unified-Wifi-Mesh
OneWifiMesh consists of 5 constituent software components that need to be individually built and executed to achieve end-to-end functionality of Wi-Fi mesh. All these components can be built on simple Linux based platform like RaspberryPi4. 
Building OneWifi
The location of OneWifi is “Name of Repository Here”. After downloading the code from the repository, please locate the makefile.inc file under generic folder. Please verify the directory names against the MACROS specified in the file. The definitions of the following must be accurate to build OneWifi for mesh functionalities.
ONE_WIFI_EM_HOME must be the directory location of the code downloaded from https://github.com/rdkcentral/unified-wifi-mesh. 
WIFI_HAL_INTERFACE must be the directory location of the code of halinterface.
WIFI_HOSTAP_BASE must be the directory location of the code of hostap.
Under this directory “make clean” and “make” commands can be executed to build OneWifi.
Building Mesh Components
Mesh Agent
After downloading the code from https://github.com/rdkcentral/unified-wifi-mesh, please locate the build directory. Please verify the MACROS definitions of the locations of code are accurate. Under build directory please locate the agent directory. Mesh Agent can be built by executing the “make clean” and “make” commands in this agent directory.
Mesh Controller
Prerequisite of building and running controller is that mysql database must be installed in your Linux based system. In case of RaspberryPi4, you can install mysql by executing “sudo apt install mariadb-server” followed by “sudo apt-get install libmysqlcppconn-dev” commands. After downloading the code from https://github.com/rdkcentral/unified-wifi-mesh, please locate the build directory. Please verify the MACROS definitions of the locations of code are accurate. Under build directory please locate the ctrl directory. Mesh Controller can be built by executing the “make clean” and “make” commands in this ctrl directory. 
Mesh CLI
After downloading the code from https://github.com/rdkcentral/unified-wifi-mesh, please locate the build directory. Please verify the MACROS definitions of the locations of code are accurate. Under build directory please locate the cli directory. Mesh CLI can be built by executing the “make clean” and “make” commands in this ctrl directory.

Building 1905.1 Abstraction and Component
Running Unified-Wifi-Mesh
To run the end-to-end stack, as mentioned before, five constituent components must be built and run.
Running Mesh Controller
To run mesh controller, you must configure and run mysql database. To configure mysql database for controller, you should execute the following. To configure your custom user account and password to be used by controller in mysql, run mysql CLI by executing “sudo mysql”. In the mysql CLI prompt, execute the command “ALTER USER 'pi'@'localhost' IDENTIFIED WITH mysql_native_password BY 'your_new_password'; FLUSH PRIVILEGES;”. Verify that the user account and password is configured by exiting the mysql program and running it again by executing “mysql -u pi -p”. When password prompt comes, type in the password. You need to create a database for controller. Execute the commad “create database OneWifiMesh;”. Verify the database is created by executing “show databases;” and “use OneWifiMesh;”. You can get more information about mysql at https://www.basedash.com/blog/how-to-install-mysql-on-a-raspberry-pi. Now you can run controller by executing “sudo ./onewifi_em_ctrl pi@”your password””.
Running Mesh CLI
After building cli, please locate the install/bin directory under mesh code directory. To run cli, execute “sudo ./onewifi_em_cli” command. The CLI command prompt will appear as <<OneWifiMeshCli>>. 
Initial Database Reset
Please use the command “reset eth0 pi” to setup the controller to accept and register mesh agents. In the above example, the eth0 argument indicates the 1905.1 abstraction layer interface name of the controller device. This can be substituted by any other interface name that you would like to be the 1905.1 AL interface. The second argument indicates the name of the device. 
SSID and Passphrase of Mesh Network
The initial reset installs default SSID and passphrases for fronthaul and backhaul networks in the system. To view the defaults, please use the “get_ssid OneWifiMesh” command in CLI. The output will look like following.
<<OneWifiMeshCli>>: get_ssid OneWifiMesh
{
    "Status":	"Success",
    "Result":	{
        "NetworkSSIDList":	[{
                "SSID":	"private_ssid",
                "PassPhrase":	"test-fronthaul",
                "Band":	["2.4", "5", "6"],
                "Enable":	true,
                "AKMsAllowed":	["dpp"],
                "SuiteSelector":	"",
                "AdvertisementEnabled":	true,
                "MFPConfig":	"Optional",
                "MobilityDomain":	"00:01:02:03:04:05",
                "HaulType":	["Fronthaul"]
            }, {
                "SSID":	"iot_ssid",
                "PassPhrase":	"test-backhaul",
                "Band":	["2.4", "5", "6"],
                "Enable":	true,
                "AKMsAllowed":	["dpp", "sae", "SuiteSelector"],
                "SuiteSelector":	"00010203",
                "AdvertisementEnabled":	true,
                "MFPConfig":	"Required",
                "MobilityDomain":	"00:01:02:03:04:05",
                "HaulType":	["IoT"]
            }, {
                "SSID":	"lnf_radius",
                "PassPhrase":	"test-backhaul",
                "Band":	["2.4", "5", "6"],
                "Enable":	true,
                "AKMsAllowed":	["dpp", "sae", "SuiteSelector"],
                "SuiteSelector":	"00010203",
                "AdvertisementEnabled":	true,
                "MFPConfig":	"Required",
                "MobilityDomain":	"00:01:02:03:04:05",
                "HaulType":	["Configurator"]
            }, {
                "SSID":	"mesh_backhaul",
                "PassPhrase":	"test-backhaul",
                "Band":	["2.4", "5", "6"],
                "Enable":	true,
                "AKMsAllowed":	["dpp", "sae", "SuiteSelector"],
                "SuiteSelector":	"00010203",
                "AdvertisementEnabled":	true,
                "MFPConfig":	"Required",
                "MobilityDomain":	"00:01:02:03:04:05",
                "HaulType":	["Backhaul"]
            }]
    }
}


Running OneWifi
After building OneWifi, please locate the install/bin directory. To run OneWifi, execute “sudo ./OneWifi -c” command.
Running Mesh Agent
After building agent, please locate the install/bin directory under mesh code directory. To run agent, execute “sudo ./onewifi_em_agent” command. Once this is executed, the mesh agent will continuously transmit 1905.1 Autoconfig Search messages to find and register with the controller. If the controller is up and running in the network, a 1905.1 Autoconfig Response, 1905.1 Autoconfig WSC, 1905.1 Topology Query and 1905.1 Topology Response will follow. At this point, the RspberryPi4 device will broadcast the Wi-Fi SSID specified in the system.

Running 1905.1 Abstraction and Components

Architecture
The fundamentals of Unified-Wifi-Mesh architecture is a layered non monolithic model. The different components of this layered model communicate with each other using standardized API sets that are published by standardized bodies like Wi-Fi Alliance or IEEE or Broadband Forum. A simplified model of this architecture is depicted below.

 
