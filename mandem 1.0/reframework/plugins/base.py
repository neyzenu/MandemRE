"""
Plugin System Base Classes
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class PluginResult:
    """Result from a plugin."""
    plugin_name: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None
    
    def add_finding(self, category: str, description: str, 
                    address: int = 0, severity: int = 1, **kwargs) -> None:
        self.findings.append({
            'category': category,
            'description': description,
            'address': address,
            'severity': severity,
            **kwargs
        })


@dataclass
class PluginContext:
    """Context passed to plugins."""
    binary: Any
    functions: Dict[int, Any] = field(default_factory=dict)
    strings: List[Any] = field(default_factory=list)
    
    def get_strings_containing(self, substring: str) -> List[Any]:
        return [s for s in self.strings 
                if hasattr(s, 'value') and substring.lower() in s.value.lower()]


class Plugin(ABC):
    """Base class for plugins."""
    
    name: str = "base_plugin"
    description: str = "Base plugin"
    version: str = "1.0.0"
    
    def __init__(self):
        self.enabled = True
    
    @abstractmethod
    def analyze(self, context: PluginContext) -> PluginResult:
        pass


class PluginManager:
    """Manages plugins."""
    
    def __init__(self):
        self.plugins: Dict[str, Plugin] = {}
    
    def register(self, plugin: Plugin) -> None:
        self.plugins[plugin.name] = plugin
        print(f"[+] Registered plugin: {plugin.name}")
    
    def list_plugins(self) -> List[Plugin]:
        return list(self.plugins.values())
    
    def run_plugin(self, name: str, context: PluginContext) -> Optional[PluginResult]:
        plugin = self.plugins.get(name)
        if not plugin:
            print(f"[!] Plugin not found: {name}")
            return None
        
        try:
            return plugin.analyze(context)
        except Exception as e:
            return PluginResult(plugin_name=name, success=False, error=str(e))
    
    def run_all(self, context: PluginContext) -> List[PluginResult]:
        results = []
        for plugin in self.plugins.values():
            if plugin.enabled:
                result = self.run_plugin(plugin.name, context)
                if result:
                    results.append(result)
        return results
    
    def print_results(self, results: List[PluginResult]) -> None:
        print("\n" + "=" * 60)
        print("PLUGIN RESULTS")
        print("=" * 60)
        
        for result in results:
            status = "✓" if result.success else "✗"
            print(f"\n[{status}] {result.plugin_name}")
            if result.error:
                print(f"    Error: {result.error}")
            elif result.summary:
                print(f"    {result.summary}")
            if result.findings:
                for f in result.findings[:5]:
                    print(f"    - {f.get('description', '')[:60]}")
