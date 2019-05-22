from weakref import WeakKeyDictionary

class BasicDescriptor:
    def __init__(self, default_val=None):
        self._backer = WeakKeyDictionary()
        self._default_val = default_val

    def __get__(self, instance, instancety=None):
        if instance not in self._backer:
            self._backer[instance] = self._default_val()
        return self._backer[instance]

    def __set__(self, instance, value):
        self._backer[instance] = value

class Subscribable(BasicDescriptor):
    def __init__(self, subscribers_prop, default_val=None):
        super().__init__(default_val=default_val)
        self._subscribers_prop = subscribers_prop

    def __set__(self, instance, value):
        old_val = super().__get__(instance)
        super().__set__(instance, value)
        subscribers = self._subscribers_prop.__get__(instance)
        for subscriber in list(subscribers):
            if subscriber(old_val, value):
                subscribers.remove(subscriber)

def create_subscribable(cls, name):
    subscribers_prop_name = '_on_{}_changed'.format(name)
    subscribers_prop = BasicDescriptor(set)
    setattr(cls, subscribers_prop_name, subscribers_prop)
    setattr(cls, name, Subscribable(subscribers_prop, lambda: None))
    subscribe_method_name = 'subscribe_to_{}'.format(name)
    def subscribe_method(self, f):
        subscribers_prop.__get__(self).add(f)
    setattr(cls, subscribe_method_name, subscribe_method)

def subscribables(*names):
    def _decorator(cls):
        for name in names:
            create_subscribable(cls, name)
        return cls
    return _decorator
