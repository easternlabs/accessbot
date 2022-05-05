import shortuuid
from re import search
from os import getenv
from .resource_grant_helper import ResourceGrantHelper
from grant_request_type import GrantRequestType
from jira.client import JIRA
from jira.exceptions import JIRAError
from ..exceptions import NotFoundException, PermissionDeniedException
from ..util import fuzzy_match, get_formatted_duration_string, convert_duration_flag_to_timedelta

eight_hours = 8 * 60

class JiraHelper(ResourceGrantHelper):
    def __init__(self, bot):
        self.__bot = bot
        self.__admin_ids = bot.get_admin_ids()
        self.__sdm_service = bot.get_sdm_service()
        self.__grant_type = GrantRequestType.ACCESS_RESOURCE
        super().__init__(bot)

        self.ngt_jira = "https://numerated.atlassian.net"
        self.username = getenv("JIRA_USERNAME", "")
        self.api_token = getenv("JIRA_API_TOKEN", "")

        self.auth_jira = JIRA(self.ngt_jira, basic_auth=(self.username, self.api_token))

    def request_access(self, message, searched_name, flags: dict = {}):
        if not self.__validate_issue(message, searched_name, flags):
            yield from super().request_access(message, searched_name, flags)
        else:
            execution_id = shortuuid.ShortUUID().random(length=6)
            operation_desc = self.get_operation_desc()
            self.__bot.log.info("##SDM## %s JiraHelper.access_%s new %s request for resource_name: %s", execution_id,
                                self.__grant_type, operation_desc, searched_name)
            try:
                sdm_object = self.get_item_by_name(searched_name, execution_id)
                sdm_account = self.__get_account(message)
                self.check_permission(sdm_object, sdm_account, searched_name)
                request_id = self.generate_grant_request_id()

                self.__bot.enter_grant_request(request_id, message, sdm_object, sdm_account, self.__grant_type,
                                               flags=flags)
                yield from self.__bot.get_approve_helper().evaluate(request_id, is_auto_approve=True)
            except NotFoundException as ex:
                self.__bot.log.error("##SDM## %s JiraHelper.access_%s %s request failed %s", execution_id,
                                     self.__grant_type, operation_desc, str(ex))
                yield str(ex)
                objects = self.get_all_items()
                if self.can_try_fuzzy_matching():
                    yield from self.__try_fuzzy_matching(execution_id, objects, searched_name)
            except PermissionDeniedException as ex:
                self.__bot.log.error("##SDM## %s JiraHelper.access_%s %s permission denied %s", execution_id,
                                     self.__grant_type, operation_desc, str(ex))
                yield str(ex)

    def __get_email(self, message):
        return self.__bot.get_sender_email(message.frm)

    def __get_account(self, message):
        sender_email = self.__get_email(message)
        return self.__sdm_service.get_account_by_email(sender_email)

    def __try_fuzzy_matching(self, execution_id, term_list, role_name):
        similar_result = fuzzy_match(term_list, role_name)
        if not similar_result:
            self.__bot.log.error("##SDM## %s JiraHelper.access_%s there are no similar %ss.", execution_id, self.__grant_type, self.__grant_type)
        else:
            self.__bot.log.error("##SDM## %s JiraHelper.access_%s similar role found: %s", execution_id, self.__grant_type, str(similar_result))
            yield f"Did you mean \"{similar_result}\"?"

    def __validate_issue(self, message, searched_name, flags):
        rv = False

        try:
            m = search(r'ENG-\d+', flags["reason"])
            issue_id = m.group(0) if m else None
            issue = self.auth_jira.issue(issue_id)
            td = convert_duration_flag_to_timedelta(flags["duration"])
            duration = td.seconds / 3600
            if issue.fields.status.name != "Closed" and duration <= eight_hours:
                email = self.__get_email(message)
                time_str = get_formatted_duration_string(td)

                self.auth_jira.add_comment(issue_id, f"Strongdmbot auto-approved a grant for {email} access to {searched_name} for {time_str}")
                rv = True
            else:
                self.__bot.log.info("##SDM## JiraHelper.access_%s will not grant automatic access.", self.__grant_type)
        except JIRAError as j:
            # Issue does not exist, just return false
            self.__bot.log.info("##SDM## JiraHelper.access_%s is not granting automatic access: %s", self.__grant_type,
                                j.text)
            pass

        return rv
