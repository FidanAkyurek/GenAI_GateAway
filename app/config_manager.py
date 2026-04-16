import json
import os
from pydantic import BaseModel
from typing import List

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

class RulesConfig(BaseModel):
    layer_regex: bool = True
    layer_deberta: bool = True
    layer_llm: bool = True
    ai_threshold: float = 0.75
    blacklist: List[str] = ["bomba", "intihar", "hack", "sql_injection", "bypass"]

class ConfigManager:
    @staticmethod
    def load_config() -> RulesConfig:
        if not os.path.exists(CONFIG_FILE):
            default_cfg = RulesConfig()
            ConfigManager.save_config(default_cfg)
            return default_cfg
        
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return RulesConfig(**data)
        except Exception as e:
            print(f"Config yüklenirken hata: {e}")
            return RulesConfig()
            
    @staticmethod
    def save_config(config: RulesConfig) -> bool:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config.model_dump(), f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Config kaydedilirken hata: {e}")
            return False
