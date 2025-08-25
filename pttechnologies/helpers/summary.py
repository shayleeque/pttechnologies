"""
Module for generating summary output of identified technologies.

Provides both console output with formatted tables and JSON output
with structured nodes and properties for vulnerability scanning results.
"""

import json
import uuid
from helpers.result_storage import storage
from ptlibs.ptprinthelper import ptprint

class Summary:
    """
    Summary generator for vulnerability scan results.
    
    Processes stored scan results to generate either formatted console output
    or structured JSON output containing identified technologies, their
    probabilities, and associated metadata.
    
    Attributes:
        args: Command line arguments and configuration.
        ptjsonlib: JSON processing library instance.
    """
    
    def __init__(self, args, ptjsonlib):
        """
        Initialize the summary generator.
        
        Args:
            args: Command line arguments and configuration settings.
            ptjsonlib: JSON processing library instance.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
    
    def run(self):
        """
        Main entry point for summary generation.
        
        Generates either console output or JSON output based on configuration.
        Returns early if no scan results are available.
        
        Returns:
            None
        """
        if not storage.get_all_records():
            return
        
        if self.args.json:
            self._generate_json_output()
        else:
            self._generate_console_output()
    
    def _generate_console_output(self):
        """
        Generate formatted console output showing identified technologies.
        
        Displays a summary table with technology names, types, and calculated
        probability percentages based on stored scan results.
        
        Returns:
            None
        """
        ptprint("Summary: Identified Technologies", "TITLE", True, colortext=True, newline_above=True)
        
        technologies = storage.get_technologies_with_version()
        
        if not technologies:
            ptprint("No technologies identified", "INFO", True, indent=4)
            return
        
        for tech_info in technologies:
            technology = tech_info["technology"]
            version = tech_info["version"]
            
            data = storage.get_data_for_technology(technology, version)
            
            if not data:
                continue
            
            probability = self._calculate_probability(data)
            
            tech_display = self._format_technology_display(technology, version, data.get("technology_type"))
            
            ptprint(f"{tech_display} ({probability}%)", "VULN", True, indent=4)
    
    def _generate_json_output(self):
        """
        Generate structured JSON output with nodes and properties.
        
        Creates a comprehensive JSON structure containing:
        - Individual technology nodes with metadata
        - Global properties mapping
        - Vulnerability list
        - Status and configuration information
        
        Returns:
            None
        """
        json_output = {
            "satid": "",
            "guid": "",
            "status": "finished",
            "message": "",
            "results": {
                "nodes": self._create_nodes(),
                "properties": storage.get_properties(),
                "vulnerabilities": self._get_vulnerabilities()
            }
        }
        
        print(json.dumps(json_output, indent=2))
    
    def _create_nodes(self):
        """
        Create technology nodes for JSON output.
        
        Converts stored technology data into structured node objects
        with unique identifiers, properties, and metadata.
        
        Returns:
            List of node dictionaries for JSON output.
        """
        nodes = []
        technologies = storage.get_technologies_with_version()
        
        for tech_info in technologies:
            technology = tech_info["technology"]
            version = tech_info["version"]
            
            data = storage.get_data_for_technology(technology, version)
            
            if not data:
                continue
            
            node = self._create_single_node(technology, version, data)
            nodes.append(node)
        
        return nodes
    
    def _create_single_node(self, technology, version, data):
        """
        Create a single technology node.
        
        Args:
            technology: Technology name string.
            version: Version string or None.
            data: Technology data dictionary from storage.
            
        Returns:
            Dictionary representing a single technology node.
        """
        node_key = str(uuid.uuid4())
        
        parent_type = self._get_parent_type(data.get("node_target_type"))
        
        description = self._create_node_description(data)
        
        node = {
            "type": "software",
            "key": node_key,
            "parent": None,
            "parentType": parent_type,
            "properties": {
                "type": self._map_software_type(data.get("technology_type")),
                "name": technology,
                "version": version or "",
                "description": description
            },
            "vulnerabilities": []
        }
        
        return node
    
    def _get_parent_type(self, node_target_type):
        """
        Map node target type to parent type.
        
        Args:
            node_target_type: Target type from technology mapping.
            
        Returns:
            String representing the parent type.
        """
        mapping = {
            "device": "group_software_device",
            "service": "group_software_service", 
            "web_app": "group_software_web_app"
        }
        return mapping.get(node_target_type, "group_software_device")
    
    def _map_software_type(self, technology_type):
        """
        Map technology type to software type for JSON output.
        
        Args:
            technology_type: Technology type from storage.
            
        Returns:
            String representing the mapped software type.
        """
        mapping = {
            "Os": "softwareTypeOs",
            "WebServer": "softwareTypeWebServer",
            "WebApp": "softwareTypeWebApp",
            "Interpret": "softwareTypeInterpreter",
            "BackendFramework": "softwareTypeFramework",
            "FrontendFramework": "softwareTypeFramework"
        }
        return mapping.get(technology_type, "softwareTypeOther")
    
    def _create_node_description(self, data):
        """
        Create description text for a node.
        
        Args:
            data: Technology data dictionary from storage.
            
        Returns:
            String description combining available information.
        """
        descriptions = data.get("descriptions", [])
        modules = data.get("modules", [])
        
        parts = []
        
        if descriptions:
            parts.extend(descriptions[:2])  # Limit to first 2 descriptions
        
        return "; ".join(parts) if parts else ""
    
    def _get_vulnerabilities(self):
        """
        Get list of vulnerability identifiers for JSON output.
        
        Returns:
            List of dictionaries containing vulnerability codes.
        """
        vulns = storage.get_vulnerabilities()
        return [{"vulnCode": vuln} for vuln in vulns]
    
    def _calculate_probability(self, data):
        """
        Calculate probability percentage for a technology.
        
        Computes average probability based on the number of occurrences
        and sum of probability values from storage.
        
        Args:
            data: Technology data dictionary containing count and probability_sum.
            
        Returns:
            Integer representing the probability percentage (0-100).
        """
        count = data.get("count", 0)
        probability_sum = data.get("probability_sum", 0)
        
        if count == 0:
            return 0
        
        average_probability = probability_sum / count
        
        return max(0, min(100, int(round(average_probability))))
    
    def _format_technology_display(self, technology, version, technology_type):
        """
        Format technology name for display output.
        
        Args:
            technology: Technology name string.
            version: Version string or None.
            technology_type: Type of technology for display formatting.
            
        Returns:
            Formatted string for display output.
        """
        display_name = technology
        
        if version:
            display_name += f" {version}"
        
        if technology_type:
            type_display = self._format_type_display(technology_type)
            display_name += f" [{type_display}]"
        
        return display_name
    
    def _format_type_display(self, technology_type):
        """
        Format technology type for display.
        
        Args:
            technology_type: Technology type string from storage.
            
        Returns:
            Human-readable type string for display.
        """
        display_mapping = {
            "Os": "OS",
            "WebServer": "Webserver", 
            "WebApp": "WebApp",
            "Interpret": "Interpreter",
            "BackendFramework": "Backend Framework",
            "FrontendFramework": "Frontend Framework"
        }
        return display_mapping.get(technology_type, technology_type)