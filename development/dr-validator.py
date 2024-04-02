import json, os, tomlkit, uuid

# Elastic Stack Version: 8.12.1

class ElasticDetectionRuleValidator:
    def __init__(self) -> None:
        # All Detection Rule Lists
        self.rule_required_fields = ["description",
                                     "name",
                                     "risk_score",
                                     "severity",
                                     "type"]
        
        self.rule_type_valid_values = ["eql",
                                       "esql",
                                       "query",
                                       "saved_query",
                                       "machine_learning",
                                       "threat_match",
                                       "threshold",
                                       "new_terms"]
        
        self.rule_severity_valid_values = ["low",
                                           "medium",
                                           "high",
                                           "critical"]
        
        self.rule_risk_score_valid_values = [i for i in range(0,101)]

        # Threshold Type Lists
        self.threshold_required_fields = ["query",
                                          "index",
                                          "threshold",
                                          "language"]
        
        self.threshold_object_required_fields = ["field",
                                                 "value"]
        
        self.threshold_cardinality_object_required_fields = ["field",
                                                             "value"]
        
        # Query Type Lists
        self.query_required_fields = ["query",
                                      "index",
                                      "language"]
        
        # Saved Query Type Lists
        self.saved_query_required_fields = ["saved_id"]

        # EQL Type Lists
        self.eql_required_fields = ["language",
                                    "query",
                                    "index"]
        
        # ES|QL Type Lists
        self.esql_required_fields = ["language",
                                     "query"]
        
        # Machine Learning Type Lists
        self.ml_required_fields = ["anomaly_threshold",
                                   "machine_learning_job_id"]
        
        # Indicator Type Lists
        self.indicator_required_fields = ["threat_index",
                                          "threat_query",
                                          "threat_mapping"]
        
        self.indicator_threat_mapping_required_fields = ["field",
                                                         "type",
                                                         "value"]
        
        # New Terms Type Lists
        self.new_terms_required_fields = ["new_terms_fields",
                                          "history_window_start",
                                          "language"]

        # ECS event.category values
        self.ecs_event_category = ["api",
                                   "authentication",
                                   "configuartion",
                                   "database",
                                   "driver",
                                   "email",
                                   "file",
                                   "host",
                                   "iam",
                                   "intrusion_detection",
                                   "library",
                                   "malware",
                                   "network",
                                   "package",
                                   "process",
                                   "registry",
                                   "session",
                                   "threat",
                                   "vulnerability",
                                   "web"]


        # Other Required Lists
        self.other_required_feilds = ["enabled",
                                      "author",
                                      "from",
                                      "interval",
                                      "max_signals",
                                      "tags",
                                      "threat",
                                      "version"]
        
        self.threat_required_fields = ["framework",
                                       "tactic"]
        
        self.threat_tactic_required_fields = ["id",
                                              "name",
                                              "reference"]
        
        self.threat_technique_required_fields = ["id",
                                                 "name",
                                                 "reference"]
        
        self.threat_subtechnique_required_fields = ["id",
                                                    "name",
                                                    "reference"]


    def __severity_recommended__(self, risk_score: int, severity: str) -> tuple[bool, str]:
        if risk_score < 22 and severity != "low":
            return (False, "The recomended severity for risk_score between {} is '{}': '{}'".format("0 - 21", "low", severity))
        elif risk_score > 21 and risk_score < 48 and severity != "medium":
            return (False, "The recomended severity for risk_score between {} is '{}': '{}'".format("22 - 47", "medium", severity))
        elif risk_score > 47 and risk_score < 74 and severity != "high":
            return (False, "The recomended severity for risk_score between {} is '{}': '{}'".format("48 - 73", "high", severity))
        elif risk_score > 73 and risk_score < 101 and severity != "critical":
            return (False, "The recomended severity for risk_score between {} is '{}': '{}'".format("74 - 100", "critical", severity))

        return (True, "All checks passed!")
    
    def __query_check__(self, rule: dict) -> tuple[bool, str]:
        for requirement in self.query_required_fields:
            if requirement not in rule.keys():
                return (False, "Query type rule missing field: '{}'".format(requirement))
        if "language" in rule.keys():
            if rule["language"] not in ["kuery", "lucene"]:
                return (False, "Query type rule language valid values {}: '{}'".format(["kuery", "lucene"], rule["language"]))
        
        return (True, "All checks passed!")
    
    def __saved_query_check__(self, rule: dict) -> tuple[bool, str]:
        for requirement in self.saved_query_required_fields:
            if requirement not in rule.keys():
                return (False, "Saved Query type rule missing field: '{}'".format(requirement)) 
        
        if isinstance(rule["saved_id"], str) and len(rule["saved_id"]) < 1:
            return (False, "Saved Query type rule saved_id must be a non-empty string: '{}'".format(rule["saved_id"])) 
        
        return (True, "All checks passed!")
    
    def __threshold_check__(self, rule: dict) -> tuple[bool, str]:
        for requirement in self.threshold_required_fields:
            if requirement not in rule.keys():
                return (False, "Threshold type rule missing field: '{}'".format(requirement))
        if "language" in rule.keys():
            if rule["language"] not in ["kuery", "lucene"]:
                return (False, "Threshold type rule invalid language must be one of the following {}: '{}'".format(["kuery", "lucene"], rule["language"]))
        
        for requirement in self.threshold_object_required_fields:
            if requirement not in rule["threshold"].keys():
                return (False, "Threshold type rule threshold object missing: '{}'".format(requirement))
            
        if  isinstance(rule["threshold"]["field"], str) and len(rule["threshold"]["field"] < 1):
            return (False, "Threshold type rule threshold.field '{}' must be a non-empty string: '{}'".format(type(rule["threshold"]["field"]), rule["threshold"]["field"]))
        
        if  not isinstance(rule["threshold"]["value"], int):
            return (False, "Threshold type rule threshold.field '{}' must be a integer: '{}'".format(type(rule["threshold"]["value"]), rule["threshold"]["value"]))
        
        if "cardinality" in rule["threshold"].keys():
            if isinstance(rule["threshold"]["cardinality"], list) and len(rule["threshold"]["cardinality"]) == 1:
                for requirement in self.threshold_cardinality_object_required_fields:
                    if requirement not in rule["threshold"]["cardinality"][0].keys():
                        return (False, "Threshold type rule threshold.cardinality object missing: '{}'".format(requirement))
                if not isinstance(rule["threshold"]["cardinality"][0]["value"], int):
                    return (False, "Threshold type rule threshold.cardinality.value must be a integer: '{}'".format(type(rule["threshold"]["cardinality"][0]["value"])))
            elif isinstance(rule["threshold"]["cardinality"], list) and len(rule["threshold"]["cardinality"]) > 1:
                return (False, "Threshold type rule threshold.cardinality object must be an array with one element: {}".format(len(rule["threshold"]["cardinality"])))
            
        return (True, "All checks passed!")
    
    def __ml_check__(self, rule: dict) -> tuple[bool, str]:
        for requirement in self.ml_required_fields:
            if requirement not in rule.keys():
                return (False, "ML type rule missing field: '{}'".format(requirement))
        
        if not isinstance(rule["anomaly_threshold"], int):
            return (False, "ML type rule anomaly_threshold must be a integer: '{}'".format(type(rule["anomaly_threshold"])))
        elif isinstance(rule["anomaly_threshold"], int):
            if rule["anomaly_threshold"] < 0 or rule["anomaly_threshold"] > 100:
                return (False, "ML type rule anomaly_threshold must be a between {}: '{}'".format("0 - 100",rule["anomaly_threshold"]))
            
        if not isinstance(rule["machine_learning_job_id"], str):
            return (False, "ML type rule machine_learning_job_id must be a string: '{}'".format(type(rule["machine_learning_job_id"])))
        elif isinstance(rule["machine_learning_job_id"], str) and len(rule["machine_learning_job_id"]) < 1:
            return (False, "ML type rule machine_learning_job_id '{}' must be a non-empty string: '{}'".format(type(rule["machine_learning_job_id"]), rule["machine_learning_job_id"]))

        return (True, "All checks passed!")
    
    def __eql_check__(self, rule: dict) -> tuple[bool, str]:
        for requirement in self.eql_required_fields:
            if requirement not in rule.keys():
                return (False, "EQL type rule missing field: '{}'".format(requirement))
        if "language" in rule.keys():
            if rule["language"] not in ["eql"]:
                return (False, "Query type rule language valid values {}: '{}'".format(["eql"], rule["language"]))
            
        return (True, "All checks passed!")

    def __esql_check__(self, rule: dict) -> tuple[bool, str]:
        for requirement in self.esql_required_fields:
            if requirement not in rule.keys():
                return (False, "ES|QL type rule missing field: '{}'".format(requirement))
        if "language" in rule.keys():
            if rule["language"] not in ["esql"]:
                return (False, "Query type rule language valid values {}: '{}'".format(["esql"], rule["language"]))
            
        return (True, "All checks passed!")
    
    def __new_terms_check__(self, rule: dict) -> tuple[bool, str]:
        for requirement in self.esql_required_fields:
            if requirement not in rule.keys():
                return (False, "New Terms type rule missing field: '{}'".format(requirement))
        
        if "language" in rule.keys():
            if rule["language"] not in ["kuery", "lucene"]:
                return (False, "New Terms type rule language valid values {}: '{}'".format(["kuery", "lucene"], rule["language"]))
            
        return (True, "All checks passed!")

    def validate(self, rule: dict | tomlkit.TOMLDocument | str) -> tuple[bool, str]:
        if isinstance(rule, str):
            rule = json.loads(rule)
        elif isinstance(rule, tomlkit.TOMLDocument):
            rule = dict(rule)

        # Stage 1 - Required for all rule types
        for requirement in self.rule_required_fields:
            if requirement not in rule.keys():
                return (False, "Missing Required Field: {}".format(requirement))
            
        if len(rule["name"]) < 3:
            return (False, "Name is to short (must be greater 3 characters long): '{}'".format(rule["name"])) 
            
        if len(rule["description"]) < 20:
            return (False, "Description is to short (must be greater 20 characters long): '{}'".format(rule["description"]))
        
        if rule["type"] not in self.rule_type_valid_values:
            return (False, "Invalid type must be one of the following {}: '{}'".format(self.rule_type_valid_values, rule["type"]))
        
        if rule["severity"] not in self.rule_severity_valid_values:
            return (False, "Invalid severity must be one of the following {}: '{}'".format(self.rule_severity_valid_values, rule["severity"]))
        
        if rule["risk_score"] not in self.rule_risk_score_valid_values:
            return (False, "Invalid risk_score must be between 0 - 100: {}".format(rule["risk_score"]))

        check, check_risk_score_recommendation = self.__severity_recommended__(rule["risk_score"], rule["severity"])

        if not check:
            return (check, check_risk_score_recommendation)
        
        # Stage 2 - Other Required
        for requirement in self.other_required_feilds:
            if requirement not in rule.keys():
                return (False, "Missing Required Field: {}".format(requirement))
            
        if not isinstance(rule["author"], list):
            return (False, "Author must be a list: '{}'".format(type(rule["author"])))
        elif isinstance(rule["author"], list) and len(rule["author"]) < 1:
            return (False, "Author must be a non-empty list: {}".format(rule["author"]))
            
        # Threat Object and subobjects if present
        threat_pos: int = 0
        for threat in rule["threat"]:
            # Tactic Check
            for requirement in self.threat_required_fields:
                if requirement not in threat.keys():
                    return (False, "Missing Required Field for Threat[{}] Object: {}".format(threat_pos, requirement))
            for requirement in self.threat_tactic_required_fields:
                if requirement not in threat["tactic"].keys():
                        return (False, "Missing Required Field for Threat[{}].Tactic Object: {}".format(threat_pos, requirement))
            
            # Technique Check
            if "technique" in threat.keys():
                technique_pos: int = 0
                for technique in threat["technique"]:
                    for requirement in self.threat_technique_required_fields:
                        if requirement not in technique.keys():
                                return (False, "Missing Required Field for Threat[{}].Tactic.Technique[{}] Object: {}".format(threat_pos, technique_pos, requirement))
                    
                    # Subtechnique Check
                    if "subtechnique" in technique.keys():
                        subtechnique_pos: int = 0
                        for subtechnique in technique["subtechnique"]:
                            for requirement in self.threat_subtechnique_required_fields:
                                if requirement not in subtechnique.keys():
                                        return (False, "Missing Required Field for Threat[{}].Tactic.Technique[{}].Subtechnique[{}] Object: {}".format(threat_pos, technique_pos, subtechnique_pos, requirement))
                            subtechnique_pos += 1
                    technique_pos += 1
            threat_pos += 1

        # Stage 3 Rule Type Checks
        if rule["type"] == "query":
            check, message = self.__query_check__(rule)
            if not check:
                return (check, message)
        elif rule["type"] == "saved_query":
            check, message = self.__saved_query_check__(rule)
            if not check:
                return (check, message)
        elif rule["type"] == "threshold":
            check, message = self.__threshold_check__(rule)
            if not check:
                return (check, message)
        elif rule["type"] == "machine_learning":
            check, message = self.__ml_check__(rule)
            if not check:
                return (check, message)
        elif rule["type"] == "eql":
            check, message = self.__eql_check__(rule)
            if not check:
                return (check, message)
        elif rule["type"] == "esql":
            check, message = self.__esql_check__(rule)
            if not check:
                return (check, message)
        elif rule["type"] == "new_terms":
            check, message = self.__new_terms_check__(rule)
            if not check:
                return (check, message)
                 

        # Base Case    
        return (True, "All (30/30) checks have passed!")
    
if __name__ == "__main__":
    validator: ElasticDetectionRuleValidator = ElasticDetectionRuleValidator()

    CWD: str = os.getcwd()
    
    if not os.path.exists("running"):
        os.mkdir("running")

    # Get DRs to Update
    dr_2_validate: list = []

    if os.path.exists(os.path.join("running","rules_to_validate.txt")):
        with open(os.path.join("running","rules_to_validate.txt"), "r") as file:
                for line in file.readlines():
                    dr_2_validate.append(line.strip())
    else:
        if os.path.exists("detection-rules"):
            for root, dirs, files in os.walk("detection-rules"):
                for file in files:
                    if os.path.isfile(os.path.join(root,file)):
                        dr_2_validate.append(os.path.join(root,file))

    # Conver DRs to Dict-like object (JSON)
    dr_json: list = []
    for dr in dr_2_validate:
        if os.path.basename(dr).split(".")[1] == "toml":
            with open(dr, "r") as file:
                tomldoc = tomlkit.load(file)

                # Elastic Detection Rules TOML format with rule table
                if "rule" in tomldoc.keys():
                    tomldoc["enabled"] = True
                    tomldoc["interval"] = "5m"
                    tomldoc["from"] = "now-7m"
                    tomldoc["max_signals"] = 1
                    tomldoc["version"] = 1

                    for item in tomldoc["rule"].keys():
                        tomldoc[item] = tomldoc["rule"][item]

                    tomldoc.pop("rule")

                    try:
                        if "rule_id" not in tomldoc.keys():
                            tomldoc["rule_id"] = "D-"+ str(uuid.uuid4()) + "-E"
                    except:
                        pass
                    try:
                        tomldoc.pop("id")
                    except:
                        pass

                    dr_json.append({"path": dr, "dr": tomldoc})
                # Fixed TOML format without rule table
                else:
                    try:
                        if "rule_id" not in tomldoc.keys():
                            temp_dr["rule_id"] = "D-"+ str(uuid.uuid4()) + "-E"
                    except:
                        pass
                    try:
                        tomldoc.pop("id")
                    except:
                        pass

                    dr_json.append({"path": dr, "dr": tomldoc})
        elif os.path.basename(dr).split(".")[1] == "json":
            with open(dr, "r") as file:
                temp_dr: dict = json.load(file) 

                try:
                    if "rule_id" not in temp_dr.keys():
                        temp_dr["rule_id"] = "D-"+ str(uuid.uuid4()) + "-E"
                except:
                    pass
                try:
                    del(temp_dr["id"])
                except:
                    pass

                dr_json.append({"path": dr, "dr": temp_dr})


    with open(os.path.join("running","rules_to_elevate.txt"), "w")  as file:
        file.write("")

    for dr in dr_json:
        if "metadata" not in dr["dr"].keys():
            dr["dr"]["metadata"]={}
        dr["dr"]["metadata"]["managed_by"] = "GitHub"
        dr["dr"]["tags"].append("Managed By: GitHub")
        dr["dr"]["tags"] = list(set(dr["dr"]["tags"]))

        result, message = validator.validate(dr["dr"])

        print("DR @ {}: {}".format(dr["path"], (result, message)))

        if result:
            with open(os.path.join("running","rules_to_elevate.txt"), "a+")  as file:
                file.write(dr["path"] + "\n")

            if os.path.basename(dr["path"]).split(".")[1] == "toml":
                with open(dr["path"], "w")  as file:
                    tomlkit.dump(dr["dr"], file)
            elif os.path.basename(dr["path"]).split(".")[1] == "json":
                with open(dr["path"], "w")  as file:
                    json.dump(dr["dr"], file, indent=4)
        else:
            assert 0>1, "A rule has failed validation checks."

    #print(validator.validate(""))