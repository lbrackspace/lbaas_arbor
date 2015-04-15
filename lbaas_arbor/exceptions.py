

class CollectorException(Exception):
    message = "An unknown exception occurred."

    def __init__(self, **kwargs):
        super(CollectorException, self).__init__(self.message % kwargs)


class RegionException(CollectorException):
    message = "Error parsing region!"


class ConfigException(CollectorException):
    message = "Error reading configuration value: %(value)s"


class MitigationException(CollectorException):
    message = "Unable to parse mitigation: %(mitigation)s"


class AlertException(CollectorException):
    message = "Unable to parse alert: %(alert)s"


class ClassificationException(CollectorException):
    message = "Unable to properly classify mitigation: $(mitigation)s"
