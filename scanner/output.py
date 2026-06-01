"""
Output formatting and export
"""

import json
from datetime import datetime
from typing import List, Dict


class OutputFormatter:
    def save_json(self, results: List[Dict], filename: str):
        """Save scan results to JSON file"""
        output = {
            'tool': 'BushidoMap',
            'scan_time': datetime.now().isoformat(),
            'results': results
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
    
    def save_xml(self, results: List[Dict], filename: str):
        """Save scan results to XML file"""
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_lines.append('<bushidomap>')
        xml_lines.append(f'  <scantime>{datetime.now().isoformat()}</scantime>')
        xml_lines.append('  <hosts>')
        
        for result in results:
            xml_lines.append(f'    <host ip="{result["target"]}">')
            xml_lines.append('      <ports>')
            
            for port_info in result['open_ports']:
                port = port_info['port']
                state = port_info['state']
                protocol = port_info.get('protocol', 'tcp')
                service = port_info.get('service', 'unknown')
                version = port_info.get('version', '')
                
                xml_lines.append(f'        <port number="{port}" protocol="{protocol}">')
                xml_lines.append(f'          <state>{state}</state>')
                xml_lines.append(f'          <service>{service}</service>')
                if version:
                    xml_lines.append(f'          <version>{version}</version>')
                xml_lines.append('        </port>')
            
            xml_lines.append('      </ports>')
            xml_lines.append('    </host>')
        
        xml_lines.append('  </hosts>')
        xml_lines.append('</bushidomap>')
        
        with open(filename, 'w') as f:
            f.write('\n'.join(xml_lines))
