import asyncio
import re  # Added for parsing
from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.api.server_api import C2ApiClient
from incalmo.core.models.events import Event, BlockedFn
from incalmo.core.services.logging_service import IncalmoLogger
from incalmo.core.services.action_context import HighLevelContext
from incalmo.models.logging_schema import serialize
from datetime import datetime
from uuid import uuid4

class LowLevelActionOrchestrator:
    def __init__(
        self,
        logging_service: IncalmoLogger,
        forbid_by_fns: dict[str, set[str]] = None,
        forbid_by_act: dict[str, set[LowLevelAction]] = None,
    ):
        self.logger = logging_service.action_logger()
        self.flagged_fns = forbid_by_fns if forbid_by_fns is not None else {}
        self.flagged_act = forbid_by_act if forbid_by_act is not None else {}

    def _expand_ips(self, ip_input: str) -> list[str]:
        """
        Expands shorthand IP strings like '192.168.200.1,20,30' 
        into ['192.168.200.1', '192.168.200.20', '192.168.200.30']
        """
        if not ip_input or not isinstance(ip_input, str):
            return []
        
        # Split by comma
        parts = [p.strip() for p in ip_input.split(',')]
        if not parts:
            return []

        expanded = []
        # The first part is always expected to be a full IP (e.g., 192.168.1.1)
        base_ip = parts[0]
        expanded.append(base_ip)

        # If there are comma-separated suffixes (e.g., ,20,30)
        if len(parts) > 1:
            # Extract the prefix (everything before the last dot)
            if '.' in base_ip:
                prefix = base_ip.rsplit('.', 1)[0]
                for suffix in parts[1:]:
                    # Only append if the suffix is numeric (valid host ID)
                    if suffix.isdigit():
                        expanded.append(f"{prefix}.{suffix}")
                    else:
                        # If it's a full IP provided after a comma, add it as is
                        expanded.append(suffix)
        
        return expanded

    async def run_action(
        self, low_level_action: LowLevelAction, context: HighLevelContext | None = None
    ) -> list[Event]:
        action_ll_id = str(uuid4())
        if context:
            context.ll_id.append(action_ll_id)

        c2client = C2ApiClient()
        prior_agents = c2client.get_agents()

        if not self.flagged_fns:
            self.flagged_fns = {
                "192.168.200.30": ["nmap", "nikto"]
            }
        
        if not self.flagged_act:
            self.flagged_act = {
                # "192.168.200": ["deception-runbashcommand"],
            }

        blocked_events = []
        action_cmd = getattr(low_level_action, 'command', "")

        # parse and filter host IPs
        if hasattr(low_level_action, 'host') and isinstance(low_level_action.host, str):
            # "192.168.200.1,20,30" -> ["192.168.200.1", "192.168.200.20", "192.168.200.30"]
            parts = [p.strip() for p in low_level_action.host.split(',')]
            base_ip = parts[0]
            prefix = base_ip.rsplit('.', 1)[0] + "." if '.' in base_ip else ""
            
            all_targets = [base_ip] + [(prefix + p if p.isdigit() else p) for p in parts[1:]]
            
            allowed_ips = []
            for ip in all_targets:
                is_blocked = False
                # Check if this specific IP and command are in the blocklist
                if ip in self.flagged_fns:
                    for cmd in self.flagged_fns[ip]:
                        if cmd in action_cmd:
                            is_blocked = True
                            self.logger.info(
                                f"Preventing function: {cmd} on {ip}",
                                type="CMDPrevention",
                                reason=f"Command {cmd} restricted on {ip}",
                                high_level_action_id=context.hl_id if context else "",
                                low_level_action_id=action_ll_id,
                            )
                            blocked_events.append(BlockedFn(cmd, ip))
                            break
                
                if not is_blocked:
                    allowed_ips.append(ip)

            # Reassemble allowed IPs or block fully
            if not allowed_ips:
                return blocked_events # Everything was blocked

            # Rebuild shorthand string for the C2 client (e.g., "192.168.200.1,20")
            new_host = allowed_ips[0]
            if len(allowed_ips) > 1:
                new_host += "," + ",".join([ip.split('.')[-1] for ip in allowed_ips[1:]])
            
            low_level_action.host = new_host

        # 3. Execution (Note: Fixed attribute name to 'send_command' based on your file)
        command_result = c2client.send_command(low_level_action)
        await asyncio.sleep(low_level_action.command_delay)

        post_agents = c2client.get_agents()
        agent_check_result = self.check_new_agents(
            low_level_action.agent, prior_agents, post_agents
        )

        events = await low_level_action.get_result(command_result)
        events = blocked_events + events + agent_check_result
        
        self.logger.info(
            "LowLevelAction executed",
            type="LowLevelAction",
            timestamp=datetime.now().isoformat(),
            high_level_action_id=context.hl_id if context else "",
            low_level_action_id=action_ll_id,
            action_name=low_level_action.__class__.__name__,
            action_params=serialize(low_level_action),
            events=[serialize(event) for event in events],
            stderr=command_result.stderr,
            stdout=command_result.output,
        )
        return events

    def check_new_agents(self, ability_agent: Agent, prior_agents: list[Agent], post_agents: list[Agent]):
        new_agent = None
        # Find the agent that was added to the operation
        for post_agent in post_agents:
            # If the agent paw was not in the prior agents, then it was added
            if post_agent.paw not in [prior_agent.paw for prior_agent in prior_agents]:
                new_agent = post_agent
                break

        if new_agent:
            # If new agent on same host as ability agent, privledge escalation was successful
            # Check to see if any ips are shared between the ability agent and the new agent
            shared_ips = []
            for ip in ability_agent.host_ip_addrs:
                if ip in new_agent.host_ip_addrs:
                    shared_ips.append(ip)

            if len(shared_ips) > 0:
                if new_agent.username == "root":
                    return [RootAccessOnHost(new_agent)]
            else:
                return [InfectedNewHost(ability_agent, new_agent)]

        return []
