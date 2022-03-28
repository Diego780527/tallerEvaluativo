from controllers import RegisterControllers
from controllers import LoginControllers
from controllers import CreateProductoControllers
from controllers import ProductosControllers

routes = {"register": "/register", "register_controllers":RegisterControllers.as_view("register_api"),
"login": "/login", "login_controllers":LoginControllers.as_view("login_api"),
"crearproducto": "/crearproducto", "CreateProducto_controllers":CreateProductoControllers.as_view("crearp_api"),
"productos": "/productos", "productos_controllers":ProductosControllers.as_view("productos_api"),

}
