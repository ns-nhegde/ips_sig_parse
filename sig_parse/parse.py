# Copyright (C) 2023 Netskope - All Rights Reserved
import os
import re
import hashlib
import logging

logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG").upper())
LOGGER = logging.getLogger(__name__)


class Signature:
    sid_regex = re.compile(r"sid:\s*(\d+)[\s;]")
    classtype_regex = re.compile(r"classtype:\s*(\S+?)\s*;")
    revision_regex = re.compile(r"rev:\s*(\d+?)\s*;")
    flow_regex = re.compile(r"flow:\s*(\S+?)\s*;")
    name_regex = re.compile(r"msg:\s*\"(.+?)\"\s*;")
    attack_severity_regex = re.compile(r"attack-severity\s+(\S+?)\s*[,;]")
    services_regex = re.compile(r"service\s+([a-zA-Z0-9-]+?)\s*[,;]")
    cve_regex1 = re.compile(r"CVE-ID\s+(CVE-\d+-\d+)[,;]")
    cve_regex2 = re.compile(r"reference:cve,(\d+-\d+)[,;]")

    def __init__(self, rule_content):
        LOGGER.debug("Initializing Signature instance")

        self.signature_code = rule_content
        self.signature_id = self._extract_sid()
        self.classtype = self._extract_classtype()
        self.revision = self._extract_revision()
        self.flow = self._extract_flow()
        self.name = self._extract_name()
        self.action = self._extract_action()
        self.protocol = self._extract_protocol()
        self.attack_severity = self._extract_attack_severity()
        self.attack_target = self._extract_attack_target()
        self.service = self._extract_services()
        self.cve = self._extract_cve()

        LOGGER.debug("Signature instance initialization complete")

    def _extract_sid(self):
        # LOGGER.debug("Extracting sid from rule")
        matches = self.sid_regex.search(self.signature_code)

        if matches:
            sid = matches.group(1)
            # LOGGER.debug(f"Extracted sid: {int(sid)} from rule")
            return int(sid)

        # LOGGER.error("Could not extract sid from rule")
        return None

    def _extract_classtype(self):
        # LOGGER.debug("Extracting classtype from rule")
        matches = self.classtype_regex.search(self.signature_code)

        if matches:
            classtype = matches.group(1)
            # LOGGER.debug(f"Extracted classtype: {classtype} from rule")
            return classtype

        # LOGGER.error("Could not extract classtype from rule")
        return None

    def _extract_revision(self):
        # LOGGER.debug("Extracting revision from rule")
        matches = self.revision_regex.search(self.signature_code)

        if matches:
            revision = matches.group(1)
            # LOGGER.debug(f"Extracted revision: {revision} from rule")
            return int(revision)

        # LOGGER.error("Could not extract revision from rule")
        return None

    def _extract_flow(self):
        # LOGGER.debug("Extracting flow from rule")
        matches = self.flow_regex.search(self.signature_code)

        if matches:
            flow = matches.group(1)
            # LOGGER.debug(f"Extracted flow: {flow} from rule")
            return flow

        # LOGGER.error("Could not extract flow from rule")
        return None

    def _extract_name(self):
        # LOGGER.debug("Extracting name from rule")
        matches = self.name_regex.search(self.signature_code)

        if matches:
            name = matches.group(1)
            # LOGGER.debug(f"Extracted name: {name} from rule")
            return name

        # LOGGER.error("Could not extract name from rule")
        return None

    def _extract_action(self):
        # LOGGER.debug("Extracting action from rule")
        action = self.signature_code.split(" ")[0].lower()

        if action:
            # LOGGER.debug(f"Extracted action: {action} from rule")
            return action

        # LOGGER.error("Could not extract action from rule")
        return None

    def _extract_protocol(self):
        # LOGGER.debug("Extracting protocol from rule")
        protocol = self.signature_code.split(" ")[1].lower()

        if protocol:
            # LOGGER.debug(f"Extracted protocol: {protocol} from rule")
            return protocol

        # LOGGER.error("Could not extract protocol from rule")
        return None

    def _extract_attack_severity(self):
        # LOGGER.debug("Extracting attack-severity from rule")
        matches = self.attack_severity_regex.search(self.signature_code)

        if matches:
            attack_severity = matches.group(1)
            # LOGGER.debug(f"Extracted attack-severity: {attack_severity} from rule")
            return attack_severity

        # LOGGER.error("Could not extract attack-severity from rule")
        return None

    def __get_target(self):
        tokens = self.signature_code.split(" ")

        # Looping through the tokens until the direction operator is
        # encountered. Not doing a split(" ") and indexing directly
        # because there is no guarantee that there is only a single
        # whitespace between tokens
        while tokens.pop(0) not in ["->", "<>"]:
            # There is no expectation of infinite loop risk
            continue

        target = tokens.pop(0)
        # Looping for same reason as above
        while not target:
            # There is no expectation of infinite loop risk
            target = tokens.pop(0)

        return target.lower()

    def _extract_attack_target(self):
        """
        The attack target is *derived* from the rule's target. For example, the
        rule may target $HOME_NET, $EXTERNAL_NET, $HTTP_SERVERS, "any" or a
        specific IP address. Combined with the "flow" value, it is possible to
        derive whether an attack is client-side or server-side.
        """
        # LOGGER.debug("Deriving attack-target from rule")

        if not self.flow:
            # LOGGER.error("No flow available. Cannot derive attack-target from rule")
            return None

        target = self.__get_target()

        mapping = {
            "$home_net": {
                "to_server": "Server Side",
                "to_client": "Client Side",
                "from_server": "Client Side"
            },
            "$external_net": {
                "to_server": "Client Side",
                "to_client": "Server Side"
            },
            "$http_servers": {
                "to_server": "Server Side"
            },
            "any": {
                "to_server": "Server Side",
                "to_client": "Client Side",
                "from_server": "Server Side",
                "established": "Client and Server",
                "stateless": "Client and Server"
            },
        }

        flow_mapping = mapping.get(target, {})
        for flow_token in flow_mapping:
            if flow_token in self.flow:
                # LOGGER.debug(f"Extracted attack-target: "
                # "{flow_mapping[flow_token]} from rule")
                return flow_mapping[flow_token]

        # LOGGER.error("Could not derive attack-target from rule")
        return None

    def _extract_services(self):
        # LOGGER.debug("Extracting services from rule")
        matches = self.services_regex.findall(self.signature_code)

        if matches:
            services = ", ".join(matches)
            # LOGGER.debug(f"Extracted services: {services} from rule")
            return services

        # LOGGER.error("Could not extract services from rule")
        return None

    def _extract_cve(self):
        # LOGGER.debug("Extracting CVE from rule")
        matches = self.cve_regex1.findall(self.signature_code)

        if matches:
            cve = ",".join(matches)
            # LOGGER.debug(f"Extracted CVE: {cve} from rule")
            return cve
        else:
            # Some signatures don't specify CVE in cve_regex1 pattern
            matches = self.cve_regex2.findall(self.signature_code)
            if matches:
                cve = ",".join([f"CVE-{m}" for m in matches])
                # LOGGER.debug(f"Extracted CVE: {cve} from rule")
                return cve

        # LOGGER.error("Could not extract CVE from rule")
        return None

    @property
    def is_fastpattern(self):
        return True if "fast_pattern" in self.signature_code else False

    @property
    def contains_pcre(self):
        return True if "pcre:" in self.signature_code else False

    @property
    def rule_sha256(self):
        return hashlib.sha256(self.signature_code).hexdigest()
