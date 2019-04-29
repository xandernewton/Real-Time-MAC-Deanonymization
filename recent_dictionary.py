from collections import OrderedDict
from collections.abc import Callable

class recent_dict(OrderedDict):
    'Limit size, evicting the least recently looked-up key when full'

    # Source: http://stackoverflow.com/a/6190500/562769 adapted


    def __init__(self, default_factory=None, maxsize=5, *args, **kwds):

        if (default_factory is not None and
                not isinstance(default_factory, Callable)):
            raise TypeError('first argument must be callable')
        self.default_factory = default_factory
        self.maxsize = maxsize

        OrderedDict.__init__(self, *args, **kwds)


    def __getitem__(self, key):

        try:
            value = OrderedDict.__getitem__(self, key)
        except KeyError:
            value = self.__missing__(key)
        finally:
            self.move_to_end(key)
            return value

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > self.maxsize:
            oldest = next(iter(self))
            del self[oldest]


    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        self[key] = value = self.default_factory()
        return value


    def __reduce__(self):
        if self.default_factory is None:
            args = tuple()
        else:
            args = self.default_factory,
        return type(self), args, None, None, self.items()

    def copy(self):
        return self.__copy__()

    def __copy__(self):
        return type(self)(self.default_factory, self)

    def __deepcopy__(self, memo):
        import copy
        return type(self)(self.default_factory,
                          copy.deepcopy(self.items()))

    def __repr__(self):
        return OrderedDict.__repr__(self)






if __name__ == "__main__":

    recent_dict_1 = recent_dict(int)
    recent_dict_1['1'] = '1'

