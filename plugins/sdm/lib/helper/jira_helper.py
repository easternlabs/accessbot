import shortuuid
from re import escape, search
from os import getenv
from .resource_grant_helper import ResourceGrantHelper
from grant_request_type import GrantRequestType
from atlassian import Jira
from requests import HTTPError

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

    def request_access(self, message, searched_name, flags: dict = {}):
        if not self.__validate_issue(flags):
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
                yield from self.__record_and_notify(message, searched_name, sdm_object, flags)
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

    def __get_nick(self, message):
        return self.__bot.get_sender_nick(message.frm)

    def __get_account(self, message):
        sender_email = self.__get_email(message)
        return self.__sdm_service.get_account_by_email(sender_email)

    def __try_fuzzy_matching(self, execution_id, term_list, role_name):
        similar_result = fuzzy_match(term_list, role_name)
        if not similar_result:
            self.__bot.log.error("##SDM## %s JiraHelper.access_%s there are no similar %ss.", execution_id,
                                 self.__grant_type, self.__grant_type)
        else:
            self.__bot.log.error("##SDM## %s JiraHelper.access_%s similar role found: %s", execution_id,
                                 self.__grant_type, str(similar_result))
            yield f"Did you mean \"{similar_result}\"?"

    def __validate_issue(self, flags):
        rv = False

        try:
            auth_jira = Jira(self.ngt_jira, username=self.username, password=self.api_token)
            issue_id = self.__get_ticket(flags)
            td = convert_duration_flag_to_timedelta(flags["duration"])
            duration = td.seconds / 60
            if auth_jira.issue_exists(issue_id) and\
               auth_jira.get_issue_status(issue_id) != "Closed" and\
               duration <= eight_hours:
                rv = True
            else:
                self.__bot.log.info("##SDM## JiraHelper.access_%s will not grant automatic access.", self.__grant_type)
        except HTTPError as e:
            # Bad Jira credentials
            error_str = str(e)
            self.__bot.log.info("##SDM## JiraHelper.access_%s is not granting automatic access: %s", self.__grant_type,
                                error_str)
            pass
        except KeyError:
            # The required flags were not passed
            pass

        return rv

    def __get_ticket(self, flags):
        rv = None
        try:
            projects = self.__bot.config['JIRA_PROJECTS'].split(" ")
            for project in projects:
                regex = escape(project) + "-\d+"
                m = search(regex, flags["reason"])
                if m:
                    rv = m.group(0)
                    break
        except KeyError:
            pass
        return rv

    def __record_and_notify(self, message, searched_name, sdm_object, flags):
        issue_id = self.__get_ticket(flags)
        try:
            auth_jira = Jira(self.ngt_jira, username=self.username, password=self.api_token)
            td = convert_duration_flag_to_timedelta(flags["duration"])

            email = self.__get_email(message)
            nick = self.__get_nick(message)
            time_str = get_formatted_duration_string(td)

            field_name = "labels"
            field_value = auth_jira.issue_field_value(issue_id, field_name)
            field_value.append("SDMBOT")
            auth_jira.update_issue_field(issue_id, {field_name: field_value})

            approve_message = f"Strongdmbot auto-approved a grant giving {nick} ({email}) access to {searched_name} \
for {time_str} ({issue_id})"
            auth_jira.issue_add_comment(issue_id, approve_message)
            yield from self.__notify_admins(approve_message, message, sdm_object)
        except HTTPError as e:
            # Bad Jira credentials
            error_str = str(e)
            self.__bot.log.error("##SDM## JiraHelper.access_%s is unable to update issue: %s", self.__grant_type,
                                 error_str)
        except KeyError:
            # The required flags were not passed
            self.__bot.log.error("##SDM## JiraHelper.access_%s is unable to update issue", self.__grant_type)

    def __notify_admins(self, text, message, sdm_object):
        approvers_channel_tag = self.__bot.config['APPROVERS_CHANNEL_TAG']
        if approvers_channel_tag is not None and sdm_object.tags is not None:
            approvers_channel = sdm_object.tags.get(approvers_channel_tag)
            if approvers_channel is not None:
                try:
                    self.__bot.send(self.__bot.build_identifier(f'#{approvers_channel}'), text)
                except Exception:
                    yield "Sorry, I cannot contact the approvers for this resource, their channel is unreachable. " \
                          "Please, contact your SDM Admin. "
                return
        admins_channel = self.__bot.config['ADMINS_CHANNEL']
        if admins_channel:
            self.__bot.send(self.__bot.build_identifier(admins_channel), text)
            return
        for admin_id in self.__admin_ids:
            admin_id = self.__bot.get_rich_identifier(admin_id, message)
            self.__bot.send(admin_id, text)
