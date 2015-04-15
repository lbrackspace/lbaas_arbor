import pymysql

import lbaas_arbor.exceptions as exceptions


class Region(object):
    def __init__(self, name,
                 host, port, user, password, database):
        self.name = name
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self._check_params()

    def _check_params(self):
        return (self.host and self.port and self.user and
                self.password and self.database)

    def get_db(self):
        return pymysql.connect(
            host=self.host,
            port=self.port,
            user=self.user,
            passwd=self.password,
            db=self.database
        )

    def __str__(self):
        try:
            return self.name
        except Exception:
            return "unknown"

    @staticmethod
    def load_regions(conf):
        regions = {}
        try:
            for section in conf.sections():
                if section == 'global':
                    continue
                r = Region(
                    name=section.upper(),
                    host=conf.get(section, 'host'),
                    port=conf.getint(section, 'port'),
                    user=conf.get(section, 'user'),
                    password=conf.get(section, 'pass'),
                    database=conf.get(section, 'database')
                )
                regions[section.upper()] = r
            return regions
        except Exception:
            raise exceptions.RegionException()
