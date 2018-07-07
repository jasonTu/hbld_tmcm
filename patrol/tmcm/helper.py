import pymssql


G_SQL_SCAN_DETAIL = '''
declare @begin datetime,@end datetime
set @begin='2018-07-05'
set @end='2018-07-07'
select tb_av.VLF_FilePath, tb_av.VLF_FileName,
tb_av.CLF_ReasonCode, tb_av.CLF_LogGenerationTime
from tb_AVViruslog as tb_av join tb_EntityIPAddress as tb_ei
on tb_av.VLF_ClientGUID=tb_ei.EntityID
where tb_ei.IPAddress='192.168.1.55'
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


def do_get_scan_detail():
    '''Get scan detail helper func.'''
    with MssqlUtil('192.168.1.192', 'sa', 'puyacn#1..', 'db_ControlManager') as db:
        data = db.exc_query(G_SQL_SCAN_DETAIL)
        result = adjust_scan_detail(data)
        print(result)

def do_get_basic_info():
    pass


if __name__ == '__main__':
    '''
    with MssqlUtil('192.168.1.192', 'sa', 'puyacn#1..', 'db_ControlManager') as db:
        data = db.exc_query('select * from tb_EntityInfo')
        print(data)
    '''
    do_get_scan_detail()