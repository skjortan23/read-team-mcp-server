---
marp: true
theme: hacker
paginate: true
backgroundColor: "#000000"
color: "#33ff00"
---

![bg left](images/read-team-agents.jpeg)
# Red-Team-MCP
## A MCP Server for AI-Assisted Red Teaming
Thomas Olofsson
@skjortan
thomas@gofyeo.com

---

![bg right](/images/it-wizard.jpeg)

# About me
- Justified encient of mumu.
- Have worked with penetration testing sincdee it was just hacking.
- Have worked with AI since it was called ML.
- CTO @fyeo.io

---
![bg opacity:0.2](images/matrix-tunnel.jpeg)

## Fyeo - We secure web3
 - By code audits 
 - Anti phishing 
 - Osint monitoring

---

# Q:What is the worst thing about pentests

---

# Q:What is the worst thing about pentests
## A: Writing reports and waiting for nmap!

---
![bg opacity:0.3](images/AWS-agents.jpeg)
# Agents

- **What are agents?** Autonomous AI systems that can perform tasks pseudo autonomously
- **Capabilities:**
  - Execute complex workflows
  - Make decisions based on context
  - Use tools and APIs
  - Collaborate with other agents (And humans)

---

![bg 90%](images/agent-foor-loop.webp)

---

## Glorified for-loop
 - That can call **tools**
 - And **mcp** tools

![bg right 100%](images/agent-flow.png)

---

# Project Overview

Red-Team-MCP is a server implementing (MCP) for AI agents during red teaming exercises.

- **Purpose**: Provide tools and resources for AI agents to perform security testing
- **Target Users**: AI agents, security researchers, red team operators
- **Key Capability**: Allows AI agents to interact with security tools through a standardized interface


---

![bg right 120% opacity:0.8](images/mcp.jpeg)
# What is MCP?

---
## MCP = Model Context Protocol
- A standardized way for AI models to interact with tools and services
- Enables agents to:
  - Access external tools and data
  - Execute commands
  - Process results
  - Make decisions based on outcomes

---
![bg opacity:0.35](images/old-machine.jpeg)

# How MCP Works

- **Architecture:**
  - It's a glorified rest api. (But streaming). 
  - Client component allows agents to discover and use tools.
  - Standardized communication protocol
  - Runs a server or loaded via pipe

---
![bg opacity:0.3](images/old-machine.jpeg)
```python
# Server-side tool definition
@mcp.tool()
async def port_scan(params: PortScanParams) -> str:
    """Scan networks and hosts for open ports."""
    # Implementation...

# Client-side tool usage
result = await mcp_tools.port_scan(target="192.168.1.0/24", ports="1-1000")
```

---
![bg opacity:0.3](images/old-machine.jpeg)
## Architecture Overview

![](/images/architecture.png)

---
![bg left](images/red-team-2.jpeg)
## is it really red teaming?
- **Not really**: But colaborative pen testing.
- But multi-agent and human operator team work

---
![bg opacity:0.2](images/tools.jpeg)

# Key Components

1. **FastMCP Server**: Core server implementing the Model Context Protocol
2. **Port Scanner**: Discovers open ports using masscan
3. **Vulnerability Scanner**: Detects vulnerabilities using Nuclei
4. **SSH Tools**: Executes commands and performs brute force attacks
5. **Metasploit Integration**: Searches and executes exploits
6. **Domain Discovery**: Enumerates subdomains
7. **Database**: MongoDB for storing scan results and findings

---
![bg opacity:0.2](images/tools.jpeg)
# Workflow

1. **Discovery**: AI agent uses port scanning to identify open services
2. **Enumeration**: Agent uses vulnerability scanning to detect security issues
3. **Exploitation**: Agent leverages Metasploit integration to execute exploits
4. **Post-Exploitation**: Agent uses SSH tools to execute commands on compromised hosts
5. **Reporting**: Results are stored in the database for analysis

---
![bg right](images/ship-ports.jpeg)
# Port Scanner

- Uses masscan for high-speed port scanning
- Features:
  - Real-time progress updates
  - Banner grabbing had to roll my own
  - Rate limiting for controlled scanning
  - Results stored in MongoDB

---
![bg opacity:0.2](images/tools.jpeg)
# Vulnerability Scanner

- Integrates with Nuclei for vulnerability detection
- Features:
  - Template-based scanning
  - Severity filtering
  - Comprehensive vuln database (i thought)
  - Detailed findings with references

---
![bg opacity:0.2](images/tools.jpeg)
# SSH Tools

- Provides SSH command execution and brute force capabilities
- Features:
  - Username/password authentication
  - Command execution on remote hosts
  - Brute force password attacks
  - Results stored with host and port information

---
![bg opacity:0.2](images/tools.jpeg)
# Metasploit Integration

- Connects to Metasploit Framework for exploit execution
- Features:
  - Pre-populated MongoDB collection with all Metasploit exploits
  - Fast searching by platform, CVE, rank, author, or keywords
  - Exploit execution with payload configuration
  - Real-time querying from Metasploit RPC server

---

# Domain Discovery

- Enumerates subdomains from a top-level domain using subfinder
- Features:
  - Domain validation to ensure target domain resolves
  - Subdomain discovery using subfinder
  - IP resolution for each discovered subdomain
  - Database integration for storing results
  - Progress tracking and error handling
  - Concise summary with top resolved subdomains

---

# multi task capabilities
![](img.png)

---

![bg opacity:0.7 150%](images/many-agents.jpeg)

## Agents Calling Agents

- **Hierarchical agent structure**
- **Example: Hacking Agent**
  - Called by main agent to perform specialized penetration testing
  - Follows complete methodology:
    1. Reconnaissance
    2. Vulnerability assessment
    3. Exploitation
    4. Post-exploitation
  - Returns structured results to calling agent

---

![bg opacity:0.7 150%](images/many-agents.jpeg)
## Using agents as tools
```python
@tool(name="hack_machine")
async def hack_machine(target_host: str, target_ports: str = "1-65535"):
    """Execute a systematic penetration test against a target machine."""
    hacking_agent = HackingAgent(...)
    await hacking_agent.initialize()
    # Execute penetration test...
```

---
![bg opacity:0.4](images/database-relations.jpeg)

# Database Structure

- MongoDB collections:
  - **scans**: Records of scan operations
  - **findings**: Detailed information about discovered ports, services, vulnerabilities
  - **exploits**: Metasploit exploit information

- Unified search across all findings
- **Shared knowledge base** for all agents

---

![bg right](images/toaster-agent.jpeg)
# Local toasters
- capable models on local hardware: **Possible**
- 10x performance increase in last 18 month
- 100x increas in performance per $

---

# Why Agents are Changing Red Teaming

- **Automation of complex workflows**
  - Agents can execute multi-step attack chains
  - Adapt to discovered vulnerabilities
  - Make decisions based on results

- **Continuous operation**
  - Agents can work 24/7 without fatigue
  - Monitor for new vulnerabilities
  - Respond to changes in the environment

- **Knowledge retention and sharing**
  - Agents store and leverage past findings
  - Share discoveries between team members
  - Build on previous results

---

# Why Use It: Focus on the Bigger Picture

- **Strategic vs. Tactical:**
  - Agents handle tactical execution
  - Humans focus on strategy and planning

- **Comprehensive coverage:**
  - Agents can methodically test everything
  - Humans can focus on high-value targets

- **Pattern recognition:**
  - Agents identify patterns across systems
  - Highlight systemic issues for human analysis

---

# Why Use It: Work Together as a Team

- **Human-Agent Collaboration:**
  - Agents as team members
  - Extend human capabilities
  - Augment human expertise

- **Multi-agent coordination:**
  - Specialized agents for different tasks
  - Agents sharing information
  - Coordinated attack simulations

- **Knowledge amplification:**
  - Agents learn from human experts
  - Humans learn from agent discoveries
  - Continuous improvement cycle

---

# Use Cases

1. **Automated Penetration Testing**: AI agents can perform end-to-end penetration testing
2. **Vulnerability Assessment**: Identify security issues in target systems
3. **Red Team Exercises**: Simulate real-world attacks to test defenses
4. **Security Research**: Discover and analyze new vulnerabilities
5. **Training**: Teach AI agents about security concepts and techniques

---

# Getting Started

1. Install dependencies:
   - MongoDB
   - Nuclei
   - Masscan
   - Metasploit Framework

2. Set up the database:
   ```bash
   python scripts/setup_exploits_db.py
   ```

3. Run the server:
   ```bash
   python -m red_team_mcp.fastmcp_server
   ```

---

# Thank You!

**Red-Team-MCP**: Empowering AI agents for security testing

- GitHub: [https://github.com/username/red-team-mcp](https://github.com/username/red-team-mcp)
- Documentation: [https://red-team-mcp.readthedocs.io](https://red-team-mcp.readthedocs.io)
