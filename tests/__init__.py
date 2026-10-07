import os

os.environ["WARDEN_TELEMETRY"] = "0"        # tests never write to the real events log; test_telemetry opts back in
