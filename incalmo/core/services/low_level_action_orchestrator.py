import asyncio
from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.api.server_api import C2ApiClient
from incalmo.core.models.events import Event

# modified
from incalmo.core.models.events import BlockedAction, BlockedFn

# TODO Fix these imports
# from incalmo.services.environment_state_service import (
#     EnvironmentStateService,
# )
from incalmo.core.models.events import InfectedNewHost, RootAccessOnHost
from incalmo.core.services.logging_service import IncalmoLogger
from incalmo.core.services.action_context import HighLevelContext
from incalmo.models.logging_schema import serialize
from datetime import datetime
import time
from uuid import uuid4


class LowLevelActionOrchestrator:
    def __init__(
        self,
        logging_service: IncalmoLogger,
        forbid_by_fns: dict[str, set[str]] = None,
        forbid_by_act: dict[str, set[LowLevelAction]] = None,
        # environment_state_service: EnvironmentStateService,
    ):
        # self.environment_state_service = environment_state_service
        self.logger = logging_service.action_logger()
        self.flagged_fns = forbid_by_fns
        self.flagged_act = forbid_by_act

        # Define Policy: [IP Address][Block/Allow][Low Level Policy]
        # First round: block all commands to admin server
        # NOTE: lowkey this might be insane because i think this might be blocking everyone ??? 
        self.policy = {
            "192.168.200.30": {
                "block": {
                    "AddSSHKey",
                    "CopyFile",
                    "ExploitStruts",
                    "FindSSHConfig",
                    "ListFilesInDirectory",
                    "MD5SumAttackerData",
                    "NCLateralMove",
                    "NiktoScan",
                    "ReadFile",
                    "RunBashCommand",
                    "ScanHost",
                    "ScanNetwork",
                    "ScpFile",
                    "SSHLateralMove",
                    "WGetFile",
                    "WriteFile",
                }
            }
        }


    async def run_action(
        self, low_level_action: LowLevelAction, context: HighLevelContext | None = None) -> list[Event]:
        action_ll_id = str(uuid4())
        if context:
            context.ll_id.append(action_ll_id)

        c2client = C2ApiClient()
        # Get prior agents
        prior_agents = c2client.get_agents()

        print(f"LOW LEVEL ACTION: {low_level_action}")

        # action_name = low_level_action.__class__.__name__
        # target_ips = self._get_target_ips(low_level_action)

        # admin_on_web_ip = "192.168.200.30"

        # print(f"[RUN ACTION] Action Name: {action_name}, Target: {target_ips}")

        # should_block, blocked_action_name, blocked_ip = self._check_against_policy(low_level_action)
        # print(f"[RUN ACTION] Should block: {should_block}, equals admin on web? {admin_on_web_ip in target_ips} ")



        # Run action with C2C server and get result
        command_result = c2client.send_command(low_level_action)

        # Some command delay for agents to contact the server
        await asyncio.sleep(low_level_action.command_delay)

        # Check for any new agents
        post_agents = c2client.get_agents()

        agent_check_result = self.check_new_agents(
            low_level_action.agent, prior_agents, post_agents
        )

        events = await low_level_action.get_result(command_result)
        events += agent_check_result
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
        

    
    def check_new_agents(
        self, ability_agent: Agent, prior_agents: list[Agent], post_agents: list[Agent]
    ):
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


    # for a given low action, checks against the policy
    def _check_against_policy(
        self, low_level_action: LowLevelAction
    ) -> tuple[bool, str | None, str | None]:
        """
        Returns:
            (should_block, action_name, matched_ip)
        """
        action_name = low_level_action.__class__.__name__
        target_ips = self._get_target_ips(low_level_action)

        for ip in target_ips:
            if ip in self.policy:
                blocked_actions = self.policy[ip].get("block", set())
                if action_name in blocked_actions:
                    return True, action_name, ip

        return False, None, None

    # For a given low lvel action, checks which IPs it is attempting to run on 
    def _get_target_ips(self, low_level_action: LowLevelAction) -> list[str]: 
        
        target_ips: list[str] = []

        if hasattr(low_level_action, "host") and low_level_action.host is not None:
            host_ips = getattr(low_level_action.host, "ip_addresses", [])
            if host_ips:
                target_ips.extend(host_ips)

        return target_ips