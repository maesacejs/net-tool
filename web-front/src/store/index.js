import { createStore } from 'vuex';
import axios, { formToJSON } from 'axios';

const store = createStore({
  state: {
    user: null,
    displayname: localStorage.getItem('displayname') || '',
    permissions: [],
    token: localStorage.getItem('access_token') || '',
    devices: [],
    orgDevices: [],
    error: null,
    publicInfo: [],
  },
  mutations: {
    setUser(state, user) {
      state.user = user;
    },
    setPermissions(state, permissions) {
      state.permissions = permissions;
    },
    setToken(state, token) {
      state.token = token;
      localStorage.setItem('access_token', token);
    },
    setDisplayname(state, displayname) {
      state.displayname = displayname;
      localStorage.setItem('displayname', displayname);
    },
    setPublicInfo(state, publicInfo) {
      state.publicInfo = publicInfo;
    },
    setDevices(state, devices) {
      state.devices = devices;
    },
    setOrgDevices(state, orgDevices) {
      state.orgDevices = orgDevices;
    },
    updateDevices(state, { deviceId, upDescription, upExtra, deviceName, type }) {
      const device = state.devices.find(d => d.device_id === deviceId);
      if (device) {
        device.description = upDescription;
        device.extra = upExtra;
        device.name = deviceName;
        device.type = type;
      }
    },
    setError(state, error) {
      state.error = error;
    },
    setLogout(state) {
      state.user = null;
      state.token = '';
      state.displayname = '';
      localStorage.removeItem('access_token');
      localStorage.removeItem('displayname');
    },
  },

  actions: {
    async login({ commit }, credentials) {
      try {
        const response = await axios.post('http://10.0.0.136:5000/api/login', credentials);
        if (response.data.token) {
          commit('setToken', response.data.token);
          commit('setUser', response.data.user);
          commit('setDisplayname', response.data.displayname);
          commit('setError', null);
          return true
        } else {
          commit('setError', 'Invalid credentials');
          return false
        }

      } catch (err) {
        commit('setError', 'Something went wrong, contact admin for status check');
      }
    },

    async register({ commit, state }, userData) {
      console.log(userData)
      try {
        const response = await axios.post('http://10.0.0.136:5000/api/users/register', {
          userData
        }, {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        })
        if (response.status === 201) {
          return true
        }
      } catch (err) {
        console.error('Register error:', err);
        commit('setError', 'Something went wrong, check console log, API and database');
      }
    },

    async fetchUsers({ commit, state }) {
      try {
        const response = await axios.get('http://10.0.0.136:5000/api/users/fetch', {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        })
        if (response.status === 200) {
          return response.data
        }
      } catch (err) {
        console.error('Register error:', err);
        commit('setError', 'Something went wrong, check console log, API and database');
      }
    },

    async updateUser({ commit, state }, userUpdates) {
      const user_id = userUpdates.user_id;
      try {
        const response = await axios.patch(`http://10.0.0.136:5000/api/users/update/${user_id}`,
          userUpdates, {
          headers: {
            Authorization: `Bearer ${state.token}`,
          }
        }
        );
        if (response.status === 200) {
          console.log(response.status)
        }

      } catch (err) {
        commit('setError', 'Something went wrong, contact admin for status check');
      }
    },

    async updateUserPassword({ commit, state }, new_password) {
      
      const user_id = new_password.user_id;
      console.log(user_id)
      try {
        const response = await axios.patch(`http://10.0.0.136:5000/api/users/update/password/${user_id}`,
          new_password, {
          headers: {
            Authorization: `Bearer ${state.token}`,
          }
        }
        );
        if (response.status === 200) {
          console.log(response.status)
        }

      } catch (err) {
        console.log(err)
        commit('setError', 'Something went wrong, contact admin for status check');
      }
    },

    async removeUser({ commit, state }, user_id) {
      try {
        const response = await axios.delete(`http://10.0.0.136:5000/api/users/remove/${user_id}`, {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        })
        if (response.status === 200) {
          return response.data
        }
      } catch (err) {
        console.error('Register error:', err);
        commit('setError', 'Something went wrong, check console log, API and database');
      }
    },

    async fetchDevices({ commit, state }, router) {
      try {
        const response = await axios.get('http://10.0.0.136:5000/api/devices', {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        });
        const devicesSorted = [];
        response.data[0].forEach(element => {
        if (/^\(\d{2}[A-Z]{5}-\)/.test(element.name)) {
          element.name = element.name.substring(10);
        }
        if (element.name === "False") {
          element.name = "NoName"
        } 
        if (/^\([^()]+-\)/.test(element.name)) {
          const match = element.name.match(/(.+-\))(.+)$/);
          element.name = match[2];
        }
        if (element.name === "PUBLIC_IP") {
          commit('setPublicInfo', element)
        } else {
          devicesSorted.push(element)
          }
          
        });
        commit('setDevices', devicesSorted);
        commit('setPermissions', response.data[1]);
      } catch (err) {
        if (err.status === 401) {
          commit('setLogout');
          router.push('/');
        }
        console.log(err)
        commit('setError', 'Something went wrong, contact admin for status check');
      }
    },

    async fetchDevicesOrg({ commit, state }) {
      try {
        const response = await axios.get('http://10.0.0.136:5000/api/devices', {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        });
        const prefixedDevices = [];
        response.data[0].forEach(element => {
          prefixedDevices.push(element)
        });
        commit('setOrgDevices', prefixedDevices);
      } catch (err) {
        console.log(err)
        commit('setError', 'Something went wrong, contact admin for status check');
      }
    },

    async updateDevice({ state, commit, dispatch }, { deviceId, description, extra, type, deviceName, orgCleanDeviceName }) {
      console.log(deviceId, description, extra, deviceName, orgCleanDeviceName);
      var upDescription = description;
      var upDeviceName = '';
      var orgDeviceName = '0';
      var upExtra = extra;
      const device = state.orgDevices.find(d => d.device_id === deviceId);
      console.log(device, device.name)
      if (deviceName === orgCleanDeviceName) {
        console.log(deviceName, orgCleanDeviceName)
        upDeviceName = device.name
      } else {
        if (/^\(\d{2}[A-Z]{5}-\)/.test(device.name)) {
          orgDeviceName = '1';
            if (orgCleanDeviceName === "NoName") {
              const prefix = await dispatch("generatePrefix");
              console.log(prefix)
              upDeviceName = "(" + orgCleanDeviceName + prefix + "-)" + deviceName;
              upDescription = description + " -Original name: " + orgCleanDeviceName
            } else {
                  upDeviceName = "(" + orgCleanDeviceName + "-)" + deviceName;
                  upDescription = description + " -Original name: " + orgCleanDeviceName
             }
        }
        else if (/^\(\d{2}[A-Z]{5}-\)/.test(device.name) === false && /^\([^()]+-\)/.test(device.name)) {
          orgDeviceName = '1';
          const match = device.name.match(/(\((.+)-\))(.+)$/);
          const prefix = match[1];
          upDeviceName = "(" + prefix + "-)" + deviceName;
          upDescription = description + " -Previous edited name: " + orgCleanDeviceName
        } else {
          orgDeviceName = '1';
          const prefix = dispatch("generatePrefix");
          upDeviceName = prefix + deviceName;
          upDescription = description + " -(!!) Deviceupdate with nameing error! Names: " + deviceName + " " + orgCleanDeviceName;
        }
      }

      console.log(upDeviceName, orgDeviceName,
        upDescription
      )

      try {
        const response = await axios.patch(`http://10.0.0.136:5000/api/devices/update/${deviceId}`, {
          upDescription,
          upExtra,
          upDeviceName,
          orgDeviceName,
          type,
        }, {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        });
        const status = "Edited";
        commit('updateDevices', { deviceId, upDescription, upExtra, deviceName, status, type })
        return true;
      } catch (err) {
        console.error('Update error:', err);
        commit('setError', 'Failed to update device metadata');
        throw err;
      }
    },

    generatePrefix: (context) => {
      const digits = Math.floor(Math.random() * 90 + 10); // 10–99
      const letters = Array.from({ length: 5 }, () =>
        String.fromCharCode(65 + Math.floor(Math.random() * 26))
      ).join('');
      console.log(`(${digits}${letters}-)`)
      return `${digits}${letters}`;
    },

    async removeDevice({ commit, state }, device_id) {
      console.log("Deleting", device_id)
      try {
        const response = await axios.delete(`http://10.0.0.136:5000/api/devices/remove/${device_id}`, {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        })
        if (response.status === 200) {
          return response.data
        }
      } catch (err) {
        console.error('Register error:', err);
        commit('setError', 'Something went wrong, check console log, API and database');
      }
    },
    async reScan({state}) {
      try {
        const response = await axios.get('http://10.0.0.136:5000/api/devices/rescan', {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        })
        console.log(response.status)
        if (response.status === 200) {
          return response.status
        }
      } catch (err) {
        console.error('Register error:', err);
        commit('setError', 'Something went wrong, check console log, API and database');
      }
    },
    async logout({ commit, state }) {
      try {
        await axios.post('http://10.0.0.136:5000/api/logout', {}, {
          headers: {
            Authorization: `Bearer ${state.token}`,
          },
        });
        commit('setLogout');
      } catch (err) {
        commit('setError', 'Session allready nuked');
      }
    }

  },
  getters: {
    isAuthenticated(state) {
      return !!state.token;
    },
    devices(state) {
      return state.devices;
    },
    publicInfo(state) {
      return state.publicInfo
    },
    error(state) {
      return state.error;
    },
  },
});

export default store;
