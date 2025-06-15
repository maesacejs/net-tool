import { createRouter, createWebHistory } from 'vue-router';
import Login from '../views/Login.vue';
import Devices from '../views/Devices.vue';

const routes = [
  { path: '/', component: Login },
  { path: '/devices', component: Devices, meta: { requiresAuth: true } },
];

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
});

router.beforeEach((to, from, next) => {
  if (to.meta.requiresAuth && !localStorage.getItem('access_token')) {
    next('/');
  } else {
    next();
  }
});

export default router;
