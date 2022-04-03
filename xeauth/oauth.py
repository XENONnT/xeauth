import io
import sys
import param


class XeAuthStep(param.ParameterizedFunction):
    auto_advance = param.Boolean(True)
    prompt_response = param.Parameter(instantiate=False)
    console = param.ClassSelector(io.IOBase, default=sys.stdout, 
                                  instantiate=False, pickle_default_value=False)

    def perform(self, p):
        pass

    def prompt(self, p):
        return p
    
    def __call__(self, **params):
        p = param.ParamOverrides(self, params)

        p = self.prompt(p)
        
        next = self.perform(p)

        if isinstance(next, XeAuthStep) and p.auto_advance:
            params = {k:v for k,v in params.items() if k in next.param.params()}
            next = next(**params)
        return next

