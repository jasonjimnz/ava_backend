import os
from uuid import uuid4
import dialogflow_v2 as dialogflow

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "pass.json"


class AvaBot:
    session_client = None
    session = None

    def __init__(self, project_id):
        self.session_client = dialogflow.SessionsClient()
        self.session = self.session_client.session_path(project=project_id, session=uuid4().hex)

    def process_text(self, query_text):
        text_input = dialogflow.types.TextInput(text=query_text, language_code='es')
        query_input = dialogflow.types.QueryInput(text=text_input)
        result = self.session_client.detect_intent(session=self.session, query_input=query_input)

        return result, {
            'intent': result.query_result.intent.display_name,
            'response': result.query_result.fulfillment_text
        }
