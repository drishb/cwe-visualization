
# from typing import Any
# import zipfile
# import json
# from collections import OrderedDict
# from pathlib import Path

# import requests
# import networkx as nx
# import xmltodict


# class CWECatalog:
#     data_cache_dir: Path = Path(__file__).parent / "cache"
#     cwe_data_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
#     cwe_xml_path: Path = data_cache_dir / "cwec_latest.xml"

#     def _download_cwe(self) -> None:
#         self.data_cache_dir.mkdir(parents=False, exist_ok=True)
#         zip_file_path = self.data_cache_dir / "cwec_latest.xml.zip"
#         print(f"Downloading and extracting from: {self.cwe_data_url}")
#         response = requests.get(self.cwe_data_url, stream=True)
#         response.raise_for_status()
#         with open(zip_file_path, 'wb') as file:
#             for chunk in response.iter_content(chunk_size=8192):
#                 file.write(chunk)
#         with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
#             extracted_path = zip_ref.extract(zip_ref.infolist()[0].filename, self.data_cache_dir)
#             extracted_path = Path(extracted_path)
#             extracted_path.rename(self.cwe_xml_path)
#         print(f'CWE catalog XML has been saved to {self.cwe_xml_path}')
    
#     def _load_cwe_xml(self) -> OrderedDict[str, Any]:
#         if not self.cwe_xml_path.exists():
#             self._download_cwe()
        
#         with open(self.cwe_xml_path, 'r', encoding='utf-8') as file:
#             root_obj = xmltodict.parse(file.read())
#         print(f'Loaded CWE catalog data from {self.cwe_xml_path}')
#         return root_obj
    
#     def __init__(self) -> None:
#         self._root_dict = self._load_cwe_xml()
#         self._cwe_info = self.get_simplified_cwe_entry_info()
        
#         # tree structure, based on CWE-1000 Research Concepts
#         self.tree = self._build_tree_of(view_id='1000')
#         # Each node has exactly one parent node, so we use a dict to store this relationship.
#         self.parent_map: dict[str, str] = { e[1]:e[0] for e in self.tree.edges }
#         self.graph = self._build_graph(view_id='1000')
    
#     def __getitem__(self, index: str | int) -> dict[str, Any]:
#         if isinstance(index, str):
#             if index.startswith('CWE-'):
#                 cwe_id = index
#             elif index.isnumeric():
#                 cwe_id = f'CWE-{index}'
#             else:
#                 cwe_id = ''
#         elif isinstance(index, int):
#             cwe_id = 'CWE-' + str(index)
#         else:
#             cwe_id = ''
        
#         try:
#             return self._cwe_info[cwe_id]
#         except KeyError:
#             raise KeyError(f'CWE ID not found: {index}')
    
#     @property
#     def weaknesses(self) -> list[OrderedDict]:
#         return self._root_dict['Weakness_Catalog']['Weaknesses']['Weakness']
    
#     @property
#     def categories(self) -> list[OrderedDict]:
#         return self._root_dict['Weakness_Catalog']['Categories']['Category']
    
#     @property
#     def views(self) -> list[OrderedDict]:
#         return self._root_dict['Weakness_Catalog']['Views']['View']
    
#     @property
#     def all_cwe_ids(self):
#         return self._cwe_info.keys()

#     def show_cwe_basic_info(self) -> None:
#         cwe_version = self._root_dict['Weakness_Catalog']['@Version']
#         cwe_date = self._root_dict['Weakness_Catalog']['@Date']
#         print(f'Commmon Weakness Enumeration Catalog ({cwe_version} {cwe_date})')
#         print(f"Number of weaknesses: {len(self.weaknesses)}")
#         print(f"Number of categories: {len(self.categories)}")
#         print(f"Number of views: {len(self.views)}")
#         print(f"Total entries: {len(self.all_cwe_ids)}")
    
#     def get_simplified_cwe_entry_info(self) -> dict:
#         cwe_metadata = {}

#         for weakness in self.weaknesses:
#             weakness_id = 'CWE-' + weakness['@ID']
#             weakness_name = weakness['@Name']
#             abstraction = weakness['@Abstraction']
#             description = weakness['Description']
#             vulnerability_mapping = weakness['Mapping_Notes']['Usage']
#             if weakness.get('Related_Weaknesses'):
#                 rw = weakness['Related_Weaknesses']['Related_Weakness']
#                 rw = rw if isinstance(rw, list) else [rw,]
#                 related_weaknesses = [{k[1:]: v for k, v in r.items()} for r in rw]
#             else:
#                 related_weaknesses = []
#             cwe_metadata[weakness_id] = {
#                 'cwe_entry_type': 'weakness',
#                 'name': weakness_name,
#                 'abstraction': abstraction,
#                 'description': description,
#                 'vulnerability_mapping': vulnerability_mapping,
#                 'related_weaknesses': related_weaknesses,
#             }
    
        
#         for category in self.categories:
#             category_id = 'CWE-' + category['@ID']
#             category_name = category['@Name']
#             category_summary = category['Summary']
#             if category.get('Relationships'):
#                 m = category['Relationships']['Has_Member']
#                 m = m if isinstance(m, list) else [m,]
#                 members = [
#                     {k[1:]: v for k, v in r.items()} for r in m
#                 ]
#             else:
#                 members = []
#             cwe_metadata[category_id] = {
#                 'cwe_entry_type': 'category',
#                 'name': category_name,
#                 'description': category_summary,
#                 'vulnerability_mapping': 'Prohibited',
#                 'members': members,
#             }
            
#         for view in self.views:
#             view_id = 'CWE-' + view['@ID']
#             view_name = view['@Name']
#             view_description = view['Objective']
#             if view.get('Members'):
#                 m = view['Members']['Has_Member']
#                 m = m if isinstance(m, list) else [m,]
#                 members = [
#                     {k[1:]: v for k, v in r.items()} for r in m
#                 ]
#             else:
#                 members = []
#             cwe_metadata[view_id] = {
#                 'cwe_entry_type': 'view',
#                 'name': view_name,
#                 'description': view_description,
#                 'vulnerability_mapping': 'Prohibited',
#                 'members': members,
#             }

#          return cwe_metadata
    
#     def _build_tree_of(self, view_id: str='1000') -> nx.DiGraph:
#         edges = []
#         for cwe_id in self.all_cwe_ids:
#             if rws := self[cwe_id].get('related_weaknesses'):
#                 for rw_dict in rws:
#                     if (rw_dict['Nature'] == 'ChildOf' and 
#                         rw_dict.get('View_ID') == view_id and 
#                         rw_dict.get('Ordinal') == 'Primary'):
#                         edges.append(('CWE-' + rw_dict['CWE_ID'], cwe_id, dict()))
#         for member in self[view_id]['members']:
#             edges.append(('CWE-' + view_id, 'CWE-' + member['CWE_ID'], dict()))
#         digraph = nx.DiGraph(edges)
#         assert nx.is_arborescence(digraph), '? unexpected tree view ?!'
#         return digraph

#     def _build_graph(self, view_id: str='1000') -> nx.DiGraph:
#         """heterogeneous graph of CWE entries
        
#         edge type: the nature of a related weakness
#         """
#         edges = []

#         def relationship_to_edge(_w: str, _rw: dict[str, str]) -> tuple[str, str, dict[str, str]]:
#             # we want parent ---> child, so that: (parent) ---ParentOf--> (child)
#             if _rw['Nature'] == 'ChildOf':
#                 return (
#                     'CWE-' + _rw['CWE_ID'], # the parent
#                     _w, # the child
#                     {'nature': 'ParentOf', 'ordinal': _rw.get('Ordinal', '')},
#                 )
#             else:
#                 return (
#                     _w,
#                     'CWE-' + _rw['CWE_ID'],
#                     {'nature': _rw['Nature'], 'ordinal': _rw.get('Ordinal', '')},
#                 )

#         for cwe_id in self.all_cwe_ids:
#             if rws := self[cwe_id].get('related_weaknesses'):
#                 for rw_dict in rws:
#                     if rw_dict.get('View_ID') == view_id and (rw_dict['Nature'] != 'ChildOf' or rw_dict.get('Ordinal') == 'Primary'):
#                         edges.append(relationship_to_edge(cwe_id, rw_dict))

#         for member in self[view_id]['members']:
#             edges.append((
#                 'CWE-' + view_id,
#                 'CWE-' + member['CWE_ID'],
#                 {'nature': 'HasMember'}
#             ))
        
#         digraph = nx.DiGraph(edges)
#         return digraph

#     def find_path_on_tree(self, ancestor: str, descendant: str) -> list[str] | None:
#         path = [descendant]
#         current_node = descendant
#         while current_node != ancestor:
#             if current_node == 'CWE-1000': # reaches root node, fail
#                 return None
#             current_node = self.parent_map[current_node]
#             path.append(current_node)
#         path.reverse()
#         return path
    
#     def get_pillar_weakness_ancestor(self, node: str) -> str | None:
#         path_from_root = self.find_path_on_tree('CWE-1000', node)
#         if path_from_root and len(path_from_root) > 1:
#             assert self[path_from_root[1]]['abstraction'] == 'Pillar'
#             return path_from_root[1]
#         else:
#             return None

#     def find_lca_on_tree(self, node1: str, node2: str) -> str:
#         return nx.lowest_common_ancestor(self.tree, node1, node2)


# class GraphChartData(CWECatalog):
#     abstractions = ("Compound", "Pillar", "Class", "Base", "Variant")
#     # hard-coded for now
#     top_cwe_ids = ['CWE-125', 'CWE-119', 'CWE-787', 'CWE-476', 'CWE-Other', 'CWE-416', 'CWE-20', 'CWE-190', 'CWE-200', 'CWE-399', 'CWE-120', 'CWE-401', 'CWE-264', 'CWE-362', 'CWE-189', 'CWE-772', 'CWE-835', 'CWE-617', 'CWE-369', 'CWE-415', 'CWE-400', 'CWE-122', 'CWE-770', 'CWE-22', 'CWE-908', 'CWE-284', 'CWE-674', 'CWE-254', 'CWE-295', 'CWE-59', 'CWE-193', 'CWE-287', 'CWE-269', 'CWE-834', 'CWE-667', 'CWE-310', 'CWE-17', 'CWE-754', 'CWE-843', 'CWE-755', 'CWE-909', 'CWE-404', 'CWE-665', 'CWE-191', 'CWE-79', 'CWE-252', 'CWE-78', 'CWE-681', 'CWE-89', 'CWE-704']
#     top_cwe_ids = set(top_cwe_ids)

#     def export_data(self, nodes: list[str], edges, root_node: str) -> dict:
#         # 1 export nodes
#         export_nodes = []
#         export_links = []
#         valid_node_set = set(nodes)
#         for cwe_node in nodes:
#             path_ = self.find_path_on_tree(root_node, cwe_node)
#             if path_:
#                 depth = len(path_) - 1
#             else:
#                 depth = 1
#             category = self[cwe_node].get('abstraction', 'Pillar')
#             style = {
#                 # "borderColor": usage_color_map[cwe_metadata[f"CWE-{cwe_node}"]['vulnerability_mapping']],
#                 "borderWidth": 0,
#             }
#             if cwe_node in self.top_cwe_ids:
#                 style['borderColor'] = '#9B30FF'
#                 style['borderWidth'] = 2
#                 style["opacity"] = 1.0
#             else:
#                 style["opacity"] = 1.0
#             export_nodes.append({
#                 "name": cwe_node,
#                 "value": self[cwe_node]['vulnerability_mapping'],
#                 "symbolSize": 15 - depth * 2 if cwe_node != root_node else 30,
#                 "category": category,
#                 "itemStyle": style,
#             })
#         for src, tgt, attr in edges.data('nature', default='ParentOf'):
#             if src in valid_node_set and tgt in valid_node_set:
#                 export_links.append({
#                     "source": src,
#                     "target": tgt,
#                     "value": attr,
#                     "ignoreForceLayout": False if attr in ('ParentOf', 'HasMember') else True,
#                     "lineStyle": {
#                         "type": 'solid' if attr in ('ParentOf', 'HasMember') else 'dashed',
#                     },
#                     "symbol": ["none", "arrow"],
#                     "symbolSize": 5,
#                 })
        
#         print(f"root {root_node}: {len(export_nodes)} nodes, {len(export_links)}")
#         return {
#             "nodes": export_nodes, 
#             "links": export_links, 
#             "categories": [{"name": c} for c in self.abstractions], 
#             "legends": self.abstractions
#         }
    
#     def generate_graph_data(self):
#         all_graphs = {}

#         # trees of pillar weaknesses
#         for e in self.tree.out_edges(['CWE-1000']):
#             root_node = e[1]
#             visible_nodes = []
#             for cwe_id in self.tree.nodes:
#                 if self.get_pillar_weakness_ancestor(cwe_id) == root_node:
#                     visible_nodes.append(cwe_id)
#             exported_graph = self.export_data(visible_nodes, self.tree.edges, root_node)
#             graph_name = f"Tree of {root_node}: {self[root_node]['name']}"
#             all_graphs[graph_name] = exported_graph
        
#         # graph
#         target_cwes = self.top_cwe_ids
#         visible_nodes_on_graph = set()
#         for target in target_cwes:
#             if target not in self.graph.nodes:
#                 continue
#             path = self.find_path_on_tree('CWE-1000', target)
#             if path:
#                 visible_nodes_on_graph.update(path)
#         exported_graph = self.export_data(visible_nodes_on_graph, self.graph.edges, 'CWE-1000')
#         graph_name = f"Popular Weaknesses"
#         all_graphs[graph_name] = exported_graph

#         exported_graph = self.export_data(self.graph.nodes, self.graph.edges, 'CWE-1000')
#         graph_name = f"All Weaknesses (could be very laggy)"
#         all_graphs[graph_name] = exported_graph
        
#         return all_graphs


# def main():
#     cwe_catalog = GraphChartData()
#     cwe_catalog.show_cwe_basic_info()
#     target_dir = Path(__file__).parent.parent / 'public'
#     with open(target_dir / 'cwe_metadata.json', 'w') as json_file:
#         json.dump(cwe_catalog._cwe_info, json_file, indent=0)
#     graph_data = cwe_catalog.generate_graph_data()
#     with open(target_dir / 'graph_data.json', 'w') as json_file:
#         json.dump(graph_data, json_file, indent=0)


# if __name__ == '__main__':
#     main()

from typing import Any
import zipfile
import json
from collections import OrderedDict
from pathlib import Path

import requests
import networkx as nx
import xmltodict


class CWECatalog:
    data_cache_dir: Path = Path(__file__).parent / "cache"
    cwe_data_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    cwe_xml_path: Path = data_cache_dir / "cwec_latest.xml"
    
    # Add path to vulzoo JSON
    cwe_vulzoo_json_path: Path = Path(__file__).parent.parent / "public" / "cwec_vulzoo.json"

    def _download_cwe(self) -> None:
        self.data_cache_dir.mkdir(parents=False, exist_ok=True)
        zip_file_path = self.data_cache_dir / "cwec_latest.xml.zip"
        print(f"Downloading and extracting from: {self.cwe_data_url}")
        response = requests.get(self.cwe_data_url, stream=True)
        response.raise_for_status()
        with open(zip_file_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            extracted_path = zip_ref.extract(zip_ref.infolist()[0].filename, self.data_cache_dir)
            extracted_path = Path(extracted_path)
            extracted_path.rename(self.cwe_xml_path)
        print(f'CWE catalog XML has been saved to {self.cwe_xml_path}')
    
    def _load_cwe_xml(self) -> OrderedDict[str, Any]:
        if not self.cwe_xml_path.exists():
            self._download_cwe()
        
        with open(self.cwe_xml_path, 'r', encoding='utf-8') as file:
            root_obj = xmltodict.parse(file.read())
        print(f'Loaded CWE catalog data from {self.cwe_xml_path}')
        return root_obj
    
    def _load_cwe_from_vulzoo_json(self) -> dict[str, Any]:
        """Load CWE data from the vulzoo JSON file (much faster than XML parsing)"""
        if not self.cwe_vulzoo_json_path.exists():
            raise FileNotFoundError(f"Vulzoo JSON not found: {self.cwe_vulzoo_json_path}")
        
        print(f"Loading CWE data from vulzoo JSON: {self.cwe_vulzoo_json_path}")
        with open(self.cwe_vulzoo_json_path, 'r', encoding='utf-8') as file:
            root_obj = json.load(file)
        
        print(f'✓ Successfully loaded CWE catalog from vulzoo JSON')
        return root_obj
    
    def __init__(self) -> None:
        # Try to load from vulzoo JSON first (faster), fallback to XML
        try:
            self._root_dict = self._load_cwe_from_vulzoo_json()
        except FileNotFoundError:
            print("⚠ Vulzoo JSON not found, falling back to XML download...")
            self._root_dict = self._load_cwe_xml()
        
        self._cwe_info = self.get_simplified_cwe_entry_info()
        
        # tree structure, based on CWE-1000 Research Concepts
        self.tree = self._build_tree_of(view_id='1000')
        # Each node has exactly one parent node, so we use a dict to store this relationship.
        self.parent_map: dict[str, str] = { e[1]:e[0] for e in self.tree.edges }
        self.graph = self._build_graph(view_id='1000')
    
    def __getitem__(self, index: str | int) -> dict[str, Any]:
        if isinstance(index, str):
            if index.startswith('CWE-'):
                cwe_id = index
            elif index.isnumeric():
                cwe_id = f'CWE-{index}'
            else:
                cwe_id = ''
        elif isinstance(index, int):
            cwe_id = 'CWE-' + str(index)
        else:
            cwe_id = ''
        
        try:
            return self._cwe_info[cwe_id]
        except KeyError:
            raise KeyError(f'CWE ID not found: {index}')
    
    @property
    def weaknesses(self) -> list[OrderedDict]:
        return self._root_dict['Weakness_Catalog']['Weaknesses']['Weakness']
    
    @property
    def categories(self) -> list[OrderedDict]:
        return self._root_dict['Weakness_Catalog']['Categories']['Category']
    
    @property
    def views(self) -> list[OrderedDict]:
        return self._root_dict['Weakness_Catalog']['Views']['View']
    
    @property
    def all_cwe_ids(self):
        return self._cwe_info.keys()

    def show_cwe_basic_info(self) -> None:
        cwe_version = self._root_dict['Weakness_Catalog']['@Version']
        cwe_date = self._root_dict['Weakness_Catalog']['@Date']
        print(f'Common Weakness Enumeration Catalog ({cwe_version} {cwe_date})')
        print(f"Number of weaknesses: {len(self.weaknesses)}")
        print(f"Number of categories: {len(self.categories)}")
        print(f"Number of views: {len(self.views)}")
        print(f"Total entries: {len(self.all_cwe_ids)}")
    
    def get_simplified_cwe_entry_info(self) -> dict:
        cwe_metadata = {}

        for weakness in self.weaknesses:
            weakness_id = 'CWE-' + weakness['@ID']
            weakness_name = weakness['@Name']
            abstraction = weakness['@Abstraction']
            description = weakness['Description']
            
            # Extended Description
            extended_description = weakness.get('Extended_Description', '')
            
            # Vulnerability Mapping
            vulnerability_mapping = weakness['Mapping_Notes']['Usage']
            
            # Related Weaknesses
            if weakness.get('Related_Weaknesses'):
                rw = weakness['Related_Weaknesses']['Related_Weakness']
                rw = rw if isinstance(rw, list) else [rw,]
                related_weaknesses = [{k[1:]: v for k, v in r.items()} for r in rw]
            else:
                related_weaknesses = []
            
            # Likelihood of Exploit
            likelihood_of_exploit = weakness.get('Likelihood_Of_Exploit', 'Unknown')
            
            # Background Details
            background_details = []
            if weakness.get('Background_Details'):
                bg = weakness['Background_Details'].get('Background_Detail', [])
                background_details = bg if isinstance(bg, list) else [bg]
            
            # Modes of Introduction
            modes_of_introduction = []
            if weakness.get('Modes_Of_Introduction'):
                intro = weakness['Modes_Of_Introduction']['Introduction']
                intro = intro if isinstance(intro, list) else [intro]
                for i in intro:
                    modes_of_introduction.append({
                        'phase': i.get('Phase', ''),
                        'note': i.get('Note', '')
                    })
            
            # Common Consequences
            consequences = []
            if weakness.get('Common_Consequences'):
                cons = weakness['Common_Consequences']['Consequence']
                cons = cons if isinstance(cons, list) else [cons]
                for c in cons:
                    scope = c.get('Scope', '')
                    scope = scope if isinstance(scope, list) else [scope]
                    impact = c.get('Impact', '')
                    impact = impact if isinstance(impact, list) else [impact]
                    consequences.append({
                        'scope': scope,
                        'impact': impact,
                        'note': c.get('Note', '')
                    })
            
            # Potential Mitigations
            mitigations = []
            if weakness.get('Potential_Mitigations'):
                mit = weakness['Potential_Mitigations']['Mitigation']
                mit = mit if isinstance(mit, list) else [mit]
                for m in mit:
                    mitigations.append({
                        'phase': m.get('Phase', ''),
                        'description': m.get('Description', ''),
                        'effectiveness': m.get('Effectiveness', ''),
                        'effectiveness_notes': m.get('Effectiveness_Notes', '')
                    })
            
            # Observed Examples (Real CVEs!)
            observed_examples = []
            if weakness.get('Observed_Examples'):
                obs = weakness['Observed_Examples']['Observed_Example']
                obs = obs if isinstance(obs, list) else [obs]
                for o in obs:
                    observed_examples.append({
                        'reference': o.get('Reference', ''),
                        'description': o.get('Description', ''),
                        'link': o.get('Link', '')
                    })
            
            # Detection Methods
            detection_methods = []
            if weakness.get('Detection_Methods'):
                det = weakness['Detection_Methods']['Detection_Method']
                det = det if isinstance(det, list) else [det]
                for d in det:
                    detection_methods.append({
                        'method_id': d.get('@Detection_Method_ID', ''),
                        'method': d.get('Method', ''),
                        'description': d.get('Description', ''),
                        'effectiveness': d.get('Effectiveness', '')
                    })
            
            # Applicable Platforms
            applicable_platforms = {'languages': [], 'technologies': [], 'architectures': [], 'operating_systems': []}
            if weakness.get('Applicable_Platforms'):
                ap = weakness['Applicable_Platforms']
                
                # Languages
                if ap.get('Language'):
                    lang = ap['Language']
                    lang = lang if isinstance(lang, list) else [lang]
                    applicable_platforms['languages'] = [
                        {
                            'name': l.get('@Name', l.get('@Class', '')),
                            'prevalence': l.get('@Prevalence', 'Undetermined')
                        } for l in lang
                    ]
                
                # Technologies
                if ap.get('Technology'):
                    tech = ap['Technology']
                    tech = tech if isinstance(tech, list) else [tech]
                    applicable_platforms['technologies'] = [
                        {
                            'name': t.get('@Name', t.get('@Class', '')),
                            'prevalence': t.get('@Prevalence', 'Undetermined')
                        } for t in tech
                    ]
                
                # Architectures
                if ap.get('Architecture'):
                    arch = ap['Architecture']
                    arch = arch if isinstance(arch, list) else [arch]
                    applicable_platforms['architectures'] = [
                        {
                            'name': a.get('@Name', a.get('@Class', '')),
                            'prevalence': a.get('@Prevalence', 'Undetermined')
                        } for a in arch
                    ]
                
                # Operating Systems
                if ap.get('Operating_System'):
                    os_list = ap['Operating_System']
                    os_list = os_list if isinstance(os_list, list) else [os_list]
                    applicable_platforms['operating_systems'] = [
                        {
                            'name': o.get('@Name', o.get('@Class', '')),
                            'prevalence': o.get('@Prevalence', 'Undetermined')
                        } for o in os_list
                    ]
            
            # Demonstrative Examples (Code examples)
            demonstrative_examples = []
            if weakness.get('Demonstrative_Examples'):
                demo = weakness['Demonstrative_Examples']['Demonstrative_Example']
                demo = demo if isinstance(demo, list) else [demo]
                for d in demo:
                    demo_entry = {
                        'example_id': d.get('@Demonstrative_Example_ID', ''),
                        'intro_text': d.get('Intro_Text', ''),
                        'body_text': d.get('Body_Text', [])
                    }
                    
                    # Extract code examples
                    if d.get('Example_Code'):
                        code = d['Example_Code']
                        code = code if isinstance(code, list) else [code]
                        demo_entry['code_examples'] = [
                            {
                                'nature': c.get('@Nature', ''),
                                'language': c.get('@Language', ''),
                                'code': c.get('xhtml:div', '')
                            } for c in code
                        ]
                    demonstrative_examples.append(demo_entry)
            
            # Related Attack Patterns (CAPEC)
            attack_patterns = []
            if weakness.get('Related_Attack_Patterns'):
                rap = weakness['Related_Attack_Patterns']['Related_Attack_Pattern']
                rap = rap if isinstance(rap, list) else [rap]
                attack_patterns = [r.get('@CAPEC_ID', '') for r in rap]
            
            # Alternate Terms
            alternate_terms = []
            if weakness.get('Alternate_Terms'):
                alt = weakness['Alternate_Terms']['Alternate_Term']
                alt = alt if isinstance(alt, list) else [alt]
                for a in alt:
                    alternate_terms.append({
                        'term': a.get('Term', ''),
                        'description': a.get('Description', '')
                    })
            
            # Weakness Ordinalities
            weakness_ordinalities = []
            if weakness.get('Weakness_Ordinalities'):
                wo = weakness['Weakness_Ordinalities']['Weakness_Ordinality']
                wo = wo if isinstance(wo, list) else [wo]
                weakness_ordinalities = [w.get('Ordinality', '') for w in wo]
            
            # References
            references = []
            if weakness.get('References'):
                ref = weakness['References']['Reference']
                ref = ref if isinstance(ref, list) else [ref]
                references = [r.get('@External_Reference_ID', '') for r in ref]
            
            cwe_metadata[weakness_id] = {
                'cwe_entry_type': 'weakness',
                'name': weakness_name,
                'abstraction': abstraction,
                'status': weakness.get('@Status', 'Incomplete'),
                'structure': weakness.get('@Structure', 'Simple'),
                'description': description,
                'extended_description': extended_description,
                'vulnerability_mapping': vulnerability_mapping,
                'related_weaknesses': related_weaknesses,
                'likelihood_of_exploit': likelihood_of_exploit,
                'background_details': background_details,
                'modes_of_introduction': modes_of_introduction,
                'consequences': consequences,
                'mitigations': mitigations,
                'observed_examples': observed_examples,
                'cve_count': len(observed_examples),  # Quick count
                'detection_methods': detection_methods,
                'applicable_platforms': applicable_platforms,
                'demonstrative_examples': demonstrative_examples,
                'attack_patterns': attack_patterns,
                'alternate_terms': alternate_terms,
                'weakness_ordinalities': weakness_ordinalities,
                'references': references,
            }
        
        # Categories
        for category in self.categories:
            category_id = 'CWE-' + category['@ID']
            category_name = category['@Name']
            category_summary = category['Summary']
            if category.get('Relationships'):
                m = category['Relationships']['Has_Member']
                m = m if isinstance(m, list) else [m,]
                members = [
                    {k[1:]: v for k, v in r.items()} for r in m
                ]
            else:
                members = []
            cwe_metadata[category_id] = {
                'cwe_entry_type': 'category',
                'name': category_name,
                'status': category.get('@Status', 'Incomplete'),
                'description': category_summary,
                'vulnerability_mapping': 'Prohibited',
                'members': members,
            }
            
        # Views
        for view in self.views:
            view_id = 'CWE-' + view['@ID']
            view_name = view['@Name']
            view_description = view['Objective']
            if view.get('Members'):
                m = view['Members']['Has_Member']
                m = m if isinstance(m, list) else [m,]
                members = [
                    {k[1:]: v for k, v in r.items()} for r in m
                ]
            else:
                members = []
            cwe_metadata[view_id] = {
                'cwe_entry_type': 'view',
                'name': view_name,
                'type': view.get('@Type', 'Graph'),
                'status': view.get('@Status', 'Incomplete'),
                'description': view_description,
                'vulnerability_mapping': 'Prohibited',
                'members': members,
            }

        return cwe_metadata
    
    def _build_tree_of(self, view_id: str='1000') -> nx.DiGraph:
        edges = []
        for cwe_id in self.all_cwe_ids:
            if rws := self[cwe_id].get('related_weaknesses'):
                for rw_dict in rws:
                    if (rw_dict['Nature'] == 'ChildOf' and 
                        rw_dict.get('View_ID') == view_id and 
                        rw_dict.get('Ordinal') == 'Primary'):
                        edges.append(('CWE-' + rw_dict['CWE_ID'], cwe_id, dict()))
        for member in self[view_id]['members']:
            edges.append(('CWE-' + view_id, 'CWE-' + member['CWE_ID'], dict()))
        digraph = nx.DiGraph(edges)
        assert nx.is_arborescence(digraph), '? unexpected tree view ?!'
        return digraph

    def _build_graph(self, view_id: str='1000') -> nx.DiGraph:
        """heterogeneous graph of CWE entries
        
        edge type: the nature of a related weakness
        """
        edges = []

        def relationship_to_edge(_w: str, _rw: dict[str, str]) -> tuple[str, str, dict[str, str]]:
            # we want parent ---> child, so that: (parent) ---ParentOf--> (child)
            if _rw['Nature'] == 'ChildOf':
                return (
                    'CWE-' + _rw['CWE_ID'], # the parent
                    _w, # the child
                    {'nature': 'ParentOf', 'ordinal': _rw.get('Ordinal', '')},
                )
            else:
                return (
                    _w,
                    'CWE-' + _rw['CWE_ID'],
                    {'nature': _rw['Nature'], 'ordinal': _rw.get('Ordinal', '')},
                )

        for cwe_id in self.all_cwe_ids:
            if rws := self[cwe_id].get('related_weaknesses'):
                for rw_dict in rws:
                    if rw_dict.get('View_ID') == view_id and (rw_dict['Nature'] != 'ChildOf' or rw_dict.get('Ordinal') == 'Primary'):
                        edges.append(relationship_to_edge(cwe_id, rw_dict))

        for member in self[view_id]['members']:
            edges.append((
                'CWE-' + view_id,
                'CWE-' + member['CWE_ID'],
                {'nature': 'HasMember'}
            ))
        
        digraph = nx.DiGraph(edges)
        return digraph

    def find_path_on_tree(self, ancestor: str, descendant: str) -> list[str] | None:
        path = [descendant]
        current_node = descendant
        while current_node != ancestor:
            if current_node == 'CWE-1000': # reaches root node, fail
                return None
            current_node = self.parent_map[current_node]
            path.append(current_node)
        path.reverse()
        return path
    
    def get_pillar_weakness_ancestor(self, node: str) -> str | None:
        path_from_root = self.find_path_on_tree('CWE-1000', node)
        if path_from_root and len(path_from_root) > 1:
            assert self[path_from_root[1]]['abstraction'] == 'Pillar'
            return path_from_root[1]
        else:
            return None

    def find_lca_on_tree(self, node1: str, node2: str) -> str:
        return nx.lowest_common_ancestor(self.tree, node1, node2)


class GraphChartData(CWECatalog):
    abstractions = ("Compound", "Pillar", "Class", "Base", "Variant")
    # hard-coded for now
    top_cwe_ids = ['CWE-125', 'CWE-119', 'CWE-787', 'CWE-476', 'CWE-Other', 'CWE-416', 'CWE-20', 'CWE-190', 'CWE-200', 'CWE-399', 'CWE-120', 'CWE-401', 'CWE-264', 'CWE-362', 'CWE-189', 'CWE-772', 'CWE-835', 'CWE-617', 'CWE-369', 'CWE-415', 'CWE-400', 'CWE-122', 'CWE-770', 'CWE-22', 'CWE-908', 'CWE-284', 'CWE-674', 'CWE-254', 'CWE-295', 'CWE-59', 'CWE-193', 'CWE-287', 'CWE-269', 'CWE-834', 'CWE-667', 'CWE-310', 'CWE-17', 'CWE-754', 'CWE-843', 'CWE-755', 'CWE-909', 'CWE-404', 'CWE-665', 'CWE-191', 'CWE-79', 'CWE-252', 'CWE-78', 'CWE-681', 'CWE-89', 'CWE-704']
    top_cwe_ids = set(top_cwe_ids)

    def export_data(self, nodes: list[str], edges, root_node: str) -> dict:
        # 1 export nodes
        export_nodes = []
        export_links = []
        valid_node_set = set(nodes)
        for cwe_node in nodes:
            path_ = self.find_path_on_tree(root_node, cwe_node)
            if path_:
                depth = len(path_) - 1
            else:
                depth = 1
            category = self[cwe_node].get('abstraction', 'Pillar')
            style = {
                # "borderColor": usage_color_map[cwe_metadata[f"CWE-{cwe_node}"]['vulnerability_mapping']],
                "borderWidth": 0,
            }
            if cwe_node in self.top_cwe_ids:
                style['borderColor'] = '#9B30FF'
                style['borderWidth'] = 2
                style["opacity"] = 1.0
            else:
                style["opacity"] = 1.0
            
            # Add CVE count badge for nodes with observed examples
            cve_count = self[cwe_node].get('cve_count', 0)
            
            export_nodes.append({
                "name": cwe_node,
                "value": self[cwe_node]['vulnerability_mapping'],
                "symbolSize": 15 - depth * 2 if cwe_node != root_node else 30,
                "category": category,
                "itemStyle": style,
                "cve_count": cve_count,  # Add CVE count for potential UI display
            })
        for src, tgt, attr in edges.data('nature', default='ParentOf'):
            if src in valid_node_set and tgt in valid_node_set:
                export_links.append({
                    "source": src,
                    "target": tgt,
                    "value": attr,
                    "ignoreForceLayout": False if attr in ('ParentOf', 'HasMember') else True,
                    "lineStyle": {
                        "type": 'solid' if attr in ('ParentOf', 'HasMember') else 'dashed',
                    },
                    "symbol": ["none", "arrow"],
                    "symbolSize": 5,
                })
        
        print(f"root {root_node}: {len(export_nodes)} nodes, {len(export_links)} links")
        return {
            "nodes": export_nodes, 
            "links": export_links, 
            "categories": [{"name": c} for c in self.abstractions], 
            "legends": self.abstractions
        }
    
    def generate_graph_data(self):
        all_graphs = {}

        # trees of pillar weaknesses
        for e in self.tree.out_edges(['CWE-1000']):
            root_node = e[1]
            visible_nodes = []
            for cwe_id in self.tree.nodes:
                if self.get_pillar_weakness_ancestor(cwe_id) == root_node:
                    visible_nodes.append(cwe_id)
            exported_graph = self.export_data(visible_nodes, self.tree.edges, root_node)
            graph_name = f"Tree of {root_node}: {self[root_node]['name']}"
            all_graphs[graph_name] = exported_graph
        
        # graph
        target_cwes = self.top_cwe_ids
        visible_nodes_on_graph = set()
        for target in target_cwes:
            if target not in self.graph.nodes:
                continue
            path = self.find_path_on_tree('CWE-1000', target)
            if path:
                visible_nodes_on_graph.update(path)
        exported_graph = self.export_data(visible_nodes_on_graph, self.graph.edges, 'CWE-1000')
        graph_name = f"Popular Weaknesses"
        all_graphs[graph_name] = exported_graph

        exported_graph = self.export_data(self.graph.nodes, self.graph.edges, 'CWE-1000')
        graph_name = f"All Weaknesses (could be very laggy)"
        all_graphs[graph_name] = exported_graph
        
        return all_graphs


def main():
    cwe_catalog = GraphChartData()
    cwe_catalog.show_cwe_basic_info()
    target_dir = Path(__file__).parent.parent / 'public'
    
    print(f"\n📊 Exporting metadata to {target_dir / 'cwe_metadata.json'}...")
    with open(target_dir / 'cwe_metadata.json', 'w', encoding='utf-8') as json_file:
        json.dump(cwe_catalog._cwe_info, json_file, indent=2)
    
    print(f"📊 Generating graph data...")
    graph_data = cwe_catalog.generate_graph_data()
    
    print(f"📊 Exporting graph data to {target_dir / 'graph_data.json'}...")
    with open(target_dir / 'graph_data.json', 'w', encoding='utf-8') as json_file:
        json.dump(graph_data, json_file, indent=2)
    
    print(f"\n✅ Successfully exported all data!")
    print(f"   - CWE Metadata: {len(cwe_catalog._cwe_info)} entries")
    print(f"   - Graph Views: {len(graph_data)} different visualizations")


if __name__ == '__main__':
    main()