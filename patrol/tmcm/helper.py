import re
import pymssql


G_SQL_SCAN_DETAIL = '''
declare @begin datetime,@end datetime
set @begin='{begin}'
set @end='{end}'
select tb_av.VLF_FilePath, tb_av.VLF_FileName,
tb_av.CLF_ReasonCode, tb_av.CLF_LogGenerationTime
from tb_AVViruslog as tb_av join tb_EntityIPAddress as tb_ei
on tb_av.VLF_ClientGUID=tb_ei.EntityID
where tb_ei.IPAddress='{agent}'
and CLF_LogGenerationTime between @begin and @end;
'''
G_SQL_BASIC_INFO = '''
select distinct tb_ei.EI_IPAddressList, tb_ei.EI_LastRegistrationTime,
tb_tn.LastUpdateTime, tb_pi.SPI_PatternVersion, tb_eni.SEI_EngineVersion
from tb_EntityInfo as tb_ei
join tb_TreeNode as tb_tn on tb_ei.EI_EntityID=tb_tn.Guid
join tb_AVStatusPatternInfo as tb_pi on tb_ei.EI_EntityID=tb_pi.SPI_EntityID
join tb_AVStatusEngineInfo as tb_eni on tb_ei.EI_EntityID=tb_eni.SEI_EntityID
where tb_ei.EI_Type=2
and tb_pi.SPI_PatternType=1208090624
and tb_eni.SEI_EngineType=570425346
'''


class MssqlUtil:

    '''MSSQL utility class.'''

    def __init__(self, ip, user, passwd, db, port=1433):
        self.ip = ip
        self.user = user
        self.passwd = passwd
        self.db = db
        self.port = port
        self.conn = None

    def __enter__(self):
        try:
            self.conn = pymssql.connect(self.ip, self.user, self.passwd, self.db)
        except pymssql.OperationalError:
            print('连接数据库出错，请检查数据库以及账号密码后重新操作...')
        finally:
            return self

    def __exit__(self, exc_type, exc_value, traceback):
        '''Make sure to delete the resource created.'''
        if self:
            self.conn.close()

    def __bool__(self):
        return self.conn is not None

    def exc_query(self, sql):
        cursor = self.conn.cursor()
        print('当前执行的sql语句为: \n%s' % sql)
        cursor.execute(sql)
        return cursor.fetchall()


def adjust_scan_detail(result):
    '''Adjust scan detail result for view.'''
    ret = []
    for item in result:
        aitem = {}
        aitem['sfile'] = ''.join([item[0], item[1]])
        aitem['infect_type'] = item[2]
        aitem['infect_time'] = str(item[3])
        ret.append(aitem)
    return ret


def do_get_scan_detail(db_conf, agent, begin, end):
    '''Get scan detail helper func.'''
    with MssqlUtil(db_conf['ip'], db_conf['user'], db_conf['passwd'], db_conf['db']) as db:
        data = db.exc_query(G_SQL_SCAN_DETAIL.format(
            agent=agent, begin=begin, end=end
        ))
        result = adjust_scan_detail(data)
        print(result)
    return result


def adjust_basic_info(result):
    '''Adjust osce agent basic info for view.'''
    ret = []
    for item in result:
        aitem = {}
        aitem['ip'] = item[0]
        aitem['install_date'] = str(item[1])
        aitem['last_active_date'] = str(item[2])
        aitem['engine'] = item[3].strip()
        aitem['pattern'] = item[4]
        ret.append(aitem)
    return ret


def do_get_basic_info(db_conf):
    '''Get osce agent basic info helper func.'''
    with MssqlUtil(db_conf['ip'], db_conf['user'], db_conf['passwd'], db_conf['db']) as db:
        data = db.exc_query(G_SQL_BASIC_INFO)
        result = adjust_basic_info(data)
        print(result)
    return result


def valid_date_param(param):
    '''Validate date format.'''
    date_reg = r'(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})'
    ret = re.match(date_reg, param)
    if not ret:
        return False
    if ret.group('year') == '0000' or ret.group('month') in ('0', '00') or \
            ret.group('day') in ('0', '00'):
        return False
    return True


def valid_ip_param(param):
    ip_reg = '^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    compile_ip = re.compile(ip_reg)
    if compile_ip.match(param):
        return True
    else:
        return False


def check_scan_detail_params(query_params):
    must_params = ['begin', 'end', 'agent']
    for param in must_params:
        if param not in query_params:
            return False
    if not (valid_date_param(query_params['begin']) and valid_date_param(query_params['end'])):
        return False
    if not valid_ip_param(query_params['agent']):
        return False
    return True


if __name__ == '__main__':
    '''
    with MssqlUtil('192.168.1.192', 'sa', 'puyacn#1..', 'db_ControlManager') as db:
        data = db.exc_query('select * from tb_EntityInfo')
        print(data)
    '''
    do_get_scan_detail()
    do_get_basic_info()
