# EDR-Home-Lab-Attack-and-Defense

## Objective
EDR Home Lab: Attack and Defense project aimed to establish a controlled environment for simulating a real cyber attack and endpoint detection and response. The primary focus was to ingest and analyze logs within a End Point Detection and Response Solution, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

Eric Capuano's Guide: https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?utm_campaign=post&utm_medium=web

### Skills Learned
- Setting up and configuring LimaCharlie as an EDR solution to monitor and respond to endpoint activities.
- Utilizing the Sliver framework to create and manage a C2 session for simulating attacks on a Windows endpoint.
- Payload Creation and Execution: Generating and implanting a malicious payload on a target machine to simulate a cyber attack.
- Analyzing system telemetry in LimaCharlie to detect and understand malicious activities.
- Developing and applying rules in LimaCharlie to detect, block, and mitigate various types of cyber attacks.

### Tools Used
- LimaCharlie Endpoint detection and response (EDR) solution to monitor endpoint activities, analyze telemetry, detect threats, and block malicious actions.
- Sliver C2 framework to generate payloads and manage command and control sessions for simulating attacks on the Windows endpoint.
- VMware Workstation Pro to create isolated environments for the attack and victim machines, allowing for safe and controlled simulation of cyber attacks and defenses.
- Sysmon deployed on the Windows machine to log detailed system activities, which were then analyzed by LimaCharlie.
- Windows 11 used as the operating system for the victim/endpoint machine, which was targeted by the attacks and monitored by LimaCharlie.
- Ubuntu Server served as the operating system for the attack machine where Sliver was installed and used to launch attacks.

## Steps
The first step to the lab is setting up both machines. The attack machine will run on Ubuntu Server, and the endpoint will be running Windows 11. In order for this lab to work smoothly Microsoft Defender should be turned off (along with other settings), and setting up LimaCharlie on the Windows machine as an EDR solution. LimaCharlie will have a sensor linked to the windows machine, and will be importing sysmon logs. I am also going to be installing Sliver on the Ubuntu machine as my primary attack tool.

### Disabling Microsoft Defender:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/313c429d-96e8-4553-b589-c7cb338d952c)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/cc17ccc9-bcf8-4701-90d4-92e341a9cd3f)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/f78d980c-78d4-4175-91d2-f6a2dda6ef9a)

### Setting up LimaCharlie:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/32f98a65-2dc7-4e02-9039-863c6d84fea4)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/36046fbd-76b3-4aa3-aed8-2f92334d4f57)

### Setting Up Sliver on our Ubuntu Server Machine:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/8f8b457f-6394-46cc-a4a6-d4cfaf2da996)

## The Attacks, and the Defense
The first step is to generate our payload on Sliver, and implant the malware into the Windows host machine. Then we can create a command and control session after the malware is executed on the endpoint.

### Generating our Payload

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/aa90fc0c-5357-4c4d-b05b-142c61daf1f0)

Later on the Payload name will change from CRAZY_DEEP TO BOLD_UPPER because I had to restart the process since I made an error

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/591bc518-5975-4be3-9e70-6a8f855f6047)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/e3ad62c0-af4c-481c-9740-490a3c8f392d)

##

Now that we have a live session between the two machines, the attack machine can begin peeking around, checking priveleges, getting host information, and checking what type of security the host has.

### Checking Priveleges

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/19241807-e912-4760-b1e4-06111ab467d4)

### Host information and Checking Type of Security

As you can see the text in green is the attacker implant and the red is the defensive tool

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/89cae3e0-2149-4a87-be77-fdb08473bae8)

If you look all the way to the bottom, this is how attackers become aware of what security products a victim system may be using

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/2693826f-8fb3-4c8b-a534-e6ff2afe7979)

##

On the host machine we can look inside our LimaCharlie EDR solution and see telemetry from the attacker. We can identify the payload thats running and see the IP its connected to.

### Identifying the payload:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/8974e9d0-7d4d-4517-901d-f63fe2b64f66)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/05ccb0f5-4ed6-4ec1-901f-ccdf913e76ed)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/31dd54b4-6b51-4392-a73f-11337bd420e0)

### Identifying the IP its connected to:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/3a9104d7-478f-4da2-b637-ffd87ab416d2)

##

We can also use LimaCharlie to scan the hash of the payload through VirusTotal; however, it will be clean since we just created the payload ourselves.

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/a9ef6127-8bc8-4ba3-a7b7-46b1f6e3057f)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/2e92b972-205f-4b59-a4ca-3937e2695889)

##

Now on the attack machine we can simulate an attack to steal credentials by dumping the LSASS memory. In LimaCharlie we can check the sensors, observe the telemetry, and write rules to detect the sensitive process.

### Dumping the LSASS memory:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/7c11cc77-3a8d-4fbe-883f-b190094ed89c)

### Writing rules to detect the sensitive process:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/bb10fd40-8e7b-4f1b-94bc-941ef83b3307)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/829ed006-72dd-4eef-a77d-b2fac6e0935c)

### Testing the tool to see if it finds a match:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/eb8f57c0-c7cd-452c-9ed5-ad05aa50a5cf)

##

Now instead of simply detection, we can practice using LimaCharlie to write a rule that will detect and block the attacks coming from the Sliver server. On the Ubuntu machine we can simulate parts of a ransomware attack, by attempting to delete the volume shadow copies. In LimaCharlie we can view the telemetry and then write a rule that will block the attack entirely. After we create the rule in our EDR solution, the Ubuntu machine will have no luck trying the same attack again.

### Simulate parts of a ransomware attack:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/7b2a1355-ad57-49a5-9b17-2d7251c6e01f)

### Telemetry:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/252d34fc-3e9a-4850-803e-ec5bc45c6680)

### Writing rules to block the attack entirely:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/8b41fcef-63b2-4f56-8c0a-b6b929da70ca)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/93918b98-abd8-4c7d-87f4-9561a47658b3)

(Notice: The D&R rule properly terminated the parent process since the system shell hung and failed to return anything from the whoami command because the parent process was terminated. This is effective because in a real ransomeware senario the parent process is likely the ransomeware payload or lateral movement tool that would be terminated in this case)

##

Now we will be taking advantage of a more advanced capability if our EDR sensor which is to automatically scan files or processes for the presence of malware based on a Yara signature. 

Yara is a program that is mostly used for binary or tectual pattern-based malware identification and classification. It enables researchers and security experts to create rules that characterize distinctive features of certain malware families or malevolent behaviors. By comparing them to a specified set of criteria, Yara assists in sorting through massive volumes of data to uncover harmful artifacts during system analysis. These rules may then be applied to files, processes, or even network traffic to detect possible threats. Customized detection signature creation is especially helpful for threat hunting and incident response, as it allows for the quick identification of known and even undiscovered harmful materials.

Since we already know we’re dealing with the Sliver C2 payload, we can be more targeted in our exercise by using a signature specifically looking for Sliver

### Creating a Yara rule:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/b1792be9-aad5-4fc4-8135-d9e2e562363f)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/5cf3910d-dc06-4b57-880b-16fe9d695c36)

### Creating a D&R Rules to generate alerts for Yara Detection: 

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/0ecba93d-f3b0-41b7-b4ef-ff7a90e7488a)

(Notice: we’re detecting on Yara detections not involving a PROCESS object)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/0352fe68-ad44-4735-846c-ff41115ac74b)

(Notice: this detection is looking for YARA Detections specifically involving a PROCESS object)

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/6a72d7cc-f881-4914-8928-663a95cdaa5e)

(Notice: More significantly, this response action initiates a YARA scan with the Sliver signature against the just formed EXE in addition to producing an alert for the EXE creation.)

##

Now we will test the rules by moving the payload file from and back to the orginal destination. Once the scan began and discovered Sliver inside the exe, we should receive a first alert for an exe put in the Downloads directory, followed quickly by a Yara detection. Once the scan began and discovered Sliver inside the exe, we should observe a first warning for Execution from the Downloads directory, followed quickly by a Yara detection in Memory. In order to produce the "new process event" that would cause the scanning of a process that was initiated from the Downloads directory, we will now run the Sliver payload. Once the scan began and discovered Sliver inside the EXE, we should notice a first alert for Execution from the Downloads directory, followed quickly by a YARA detection in Memory.

### Moving the payload:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/c433f716-c7d1-4ba2-bbd6-71abaafbf8b5)

(Note: The error message is because I moved the payload from that path to the destination already)

### Detection

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/c66d2c37-b10b-47fe-97cd-832986134ea2)

### Running the sliver payload:

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/bba957c4-da86-4cd2-a63f-583c2ed1a09f)

### Alerts

![image](https://github.com/Alvin-Liew/EDR-Home-Lab-Attack-and-Defense/assets/105011531/59b7a849-e55a-4139-8fd8-4ee307b1af72)

## Conclusion

We have successfully established a controlled environment for simulating real cyber attacks and implementing endpoint detection and response solutions. Utilizing Eric Capuano's guide, the lab provided hands-on experience in setting up and configuring both attack and defense tools. Key skills acquired included EDR implementation, C2 operations, payload creation, telemetry analysis, and rule writing for threat mitigation. Through practical exercises, the lab enhanced understanding of network security, attack patterns, and effective defensive strategies, demonstrating the critical role of EDR solutions in modern cybersecurity.
