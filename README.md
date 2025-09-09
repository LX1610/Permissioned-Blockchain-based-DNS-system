README.md: Permissioned Blockchain DNS Simulation

**1. System Overview**

The simulation uses five Virtual Machines (VMs) with a specific network topology:
**Validator Nodes (VM1, VM2, VM3):** The core of the blockchain, maintaining an immutable ledger.
**Lightweight Resolver (VM4):** Acts as the secure, public-facing gateway and caching layer.
**Attacker Node (VM5):** Simulates a malicious node with direct network access to the validators node.
**Client:** The host machine, used to perform standard operations and resolver-focused attacks.

---

**2. Prerequisites**

* **Go (1.18 or higher):** Installed on the host machine and all VMs.
* **VirtualBox:** Installed on your host machine.
* **Lightweight Linux OS:** An `.iso` file for a server-focused distribution (e.g., Ubuntu Server Minimal) to install on your VMs.
* **SSH Client:** For connecting to your VMs.

---

**3. Deployment Guide**

**Step 3.1: Network Setup on Host**

1.  Open VirtualBox **File > Host Network Manager**.
2.  Go to the **Host-Only Networks** tab. Ensure `vboxnet0` exists and its IP is `192.168.56.1`. **Disable the DHCP Server.**
3.  Go to the **Internal Networks** tab. Click 'Create' and name it **`blockchain-net`**.

**Step 3.2: VM Creation and Configuration**

1.  Create **five new VMs** in VirtualBox.
2.  For **VM1, VM2, VM3, VM5 (Nodes & Attacker):**
    * **Settings > Network > Adapter 1:** Set to **Internal Network**, name **`blockchain-net`**.
    * (Optional) **Adapter 2:** Set to **NAT** for internet access.
3.  For **VM4 (Resolver):**
    * **Settings > Network > Adapter 1:** Set to **Host-Only Adapter**, name **`vboxnet0`**.
    * **Settings > Network > Adapter 2:** Set to **Internal Network**, name **`blockchain-net`**.
    * (Optional) **Adapter 3:** Set to **NAT** for internet access.
4.  Install a lightweight Linux OS on each VM.

**Step 3.3: Static IP Configuration within VMs**

After installing the OS, assign static IPs.

* **Validator Nodes (VM1-3):** Assign `10.0.0.10/24`, `10.0.0.11/24`, and `10.0.0.12/24` respectively to their `blockchain-net` adapters.
* **Attacker Node (VM5):** Assign `10.0.0.30/24` to its `blockchain-net` adapter.
* **Resolver (VM4):**
    * `192.168.56.21/24` on its `vboxnet0` adapter.
    * `10.0.0.21/24` on its `blockchain-net` adapter.

**Step 3.4: Key Generation, Compilation, and Transfer**

This is a one-time process on your host machine.

1.  **Generate Keys:**
    ```bash
    go run generate_keys.go
    ```
    This creates the `validator_keys/` folder.
2.  **Compile Apps:**
    ```bash
    go build -o node_app ./cmd/node
    go build -o resolver_app ./cmd/resolver
    go build -o attacker_app ./cmd/attacker
    go build -o client_app ./cmd/client (client_app.exe for Windows)
    ```
3.  **Transfer Files:** Use `scp` to copy the compiled apps and `validator_keys/` folder to each VM.

    * `scp node_app user@10.0.0.10:/path/`
    * `scp -r validator_keys/ user@10.0.0.10:/path/`

---

**4. Running the Simulation**

Use separate SSH sessions to launch each component in the correct order.

1.  **Start Validator Nodes (VM1, VM2, VM3):**
    ```bash
    ./node_app -id validator-1 -api :8081 -peers [http://10.0.0.11:8081](http://10.0.0.11:8081),[http://10.0.0.12:8081](http://10.0.0.12:8081) > nodeA.log 2>&1 &
    # ... and similar for VM2 and VM3
    ```
2.  **Start Resolver (VM4):**
    ```bash
    ./resolver_app -id main-resolver -api 192.168.56.21:8080 -nodes [http://10.0.0.10:8081](http://10.0.0.10:8081),[http://10.0.0.11:8081](http://10.0.0.11:8081),[http://10.0.0.12:8081](http://10.0.0.12:8081) > resolver.log 2>&1 &
    ```
3.  **Start Attacker (VM5):**
    ```bash
    ./attacker_app > attacker.log 2>&1 &
    ```
    (Logging is optional for the above steps, just remove the "resolver.log 2>&1 &", if logging is not needed)
4.  **Run Client (Host Machine):**
    ```bash
    ./client_app
    ```

You can now use the `client_app` and `attacker_app` menus to perform operations and attacks, observing the results in the log files on all VMs.
