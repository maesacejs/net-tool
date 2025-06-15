<template>
  <div class="container">
    <div class="columns top-buffer">
      <div class="column is-2">
        <div class="card-image has-text-centered t-aligne">
          <figure class="image is-128x128 is-inline-block">
            <img src="../assets/web-logo.jpg" />
          </figure>
        </div>
      </div>
      <div class="column is-4 top-buffer">
        <div class="box">
          <div class="columns">
            <div class="column is-7">
              <p>You are logged in as: <b>{{ displayname }}</b> </p>
              <!-- Which local IP are beeing used.-->
              <p v-if="permissions.modifying === 1">You have <b>edit</b> rights.</p>
              <p v-if="permissions.admin_users === 1">You have <b>admin</b> rights.</p>
            </div>
            <div class="column">
              <div>
                <button v-if="permissions.admin_users === 1" class="button is-small is-dark is-info" @click="showModal = true">
                User administration</button></div>
              <div>
                <button v-if="permissions.modifying === 1" class="button is-small is-dark is-warning top-buffer-small" @click="reScanExisting()">
                Scan network</button>
              </div>
            </div>
        </div>
        </div>
      </div>
        <div  v-if="permissions.admin_users === 1" class="modal" :class="{ 'is-active': showModal }">
      <div class="modal-background" @click="showModal = false"></div>

      <div class="modal-card">
        <header class="modal-card-head">
          <p class="modal-card-title">New user</p>
          <button class="delete" aria-label="close" @click="showModal = false"></button>
        </header>

        <section class="modal-card-body">
          <UserRegister />
        </section>
      </div>
    </div>
      <div class="column is-3 is-offset-3 top-buffer">
        <div class="box">
      <div><button @click="userLogout()" class="button is-dark stick-right">Logout</button></div>
       <div>The public IP is: <b>{{ publicInfo.ip_address }} </b></div>
       <div v-if="publicInfo.extra">The ISP is: <b>{{ publicInfo.extra }} </b></div>
       </div>
      </div>
    </div>
    <div class="columns top-buffer">
      <table>
        <thead>
          <tr>
            <!-- <th>Device ID</th> -->
            <th>Name</th>
            <th>Network</th>
            <th v-if="permissions.modifying === 1">MAC address</th>
            <th v-if="permissions.modifying === 1">Status</th>
            <th style="min-width: fit-content;" v-if="permissions.modifying === 1">Last seen</th>
            <th v-if="permissions.modifying === 1">Description</th>
            <th v-if="permissions.modifying === 1">Type</th>
            <th v-if="permissions.modifying === 1">Extra</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="device in devices" :key="device.device_id">
            <!-- <td>{{ device.device_id }}</td> -->

            <td v-if="permissions.modifying === 1">
              <span v-if="!editableDevices[device.device_id].editing">{{ device.name }}</span>
              <input v-else v-model="editableDevices[device.device_id].deviceName" />
            </td>
            <td v-else>
              {{ device.name }}
            </td>

            <td>
              <p>IP: <b>{{ device.ip_address }}</b></p>
              <p class="smaller-font" v-if="permissions.modifying === 1">Mask: <i>{{ device.netmask }}</i></p>
              <p class="smaller-font" v-if="permissions.modifying === 1">GW: <i>{{ device.gateway }}</i></p>
            </td>
            <td v-if="permissions.modifying === 1">{{ device.mac_address }}</td>
            <td v-if="device.status === 'new' && permissions.modifying === 1"><b>{{ device.status }}</b></td>
            <td v-if="device.status != 'new' && permissions.modifying === 1"> {{ device.status }}</td>
            <td v-if="permissions.modifying === 1">{{ device.lastseen }}</td>

            <td v-if="permissions.modifying === 1">
              <span v-if="!editableDevices[device.device_id].editing">{{ device.description }}</span>
              <input v-else v-model="editableDevices[device.device_id].description" />
            </td>
            <td v-else v-if="permissions.modifying === 1">
              {{ device.description }}
            </td>

            <td v-if="permissions.modifying === 1">
              <span v-if="!editableDevices[device.device_id].editing">{{ device.type }}</span>
              <select v-else v-model="editableDevices[device.device_id].type">
                  <option selected>{{ device.type }}</option>
                  <option>Phone</option>
                  <option>Computer</option>
                  <option>Server</option>
                  <option>Printer/Scanner</option>
                  <option>Camera</option>
                  <option>IOT</option>
                  <option>Unknown</option>
             </select>
            </td>
            <td v-else v-if="permissions.modifying === 1">
              {{ device.type }}
            </td>

            <td v-if="permissions.modifying === 1" style="max-width: 300px;">
              <span v-if="!editableDevices[device.device_id].editing">
                <pre>{{ formatExtra(device.extra) }}</pre>
              </span>
              <textarea v-else v-model="editableDevices[device.device_id].extra"></textarea>
            </td>
            <td v-else style="max-width: 300px;" v-if="permissions.modifying === 1">
              <pre>{{ formatExtra(device.extra) }}</pre>
            </td>

            <td v-if="permissions.modifying === 1">
              <button class="button is-small is-success is-dark" @click="toggleEdit(device.device_id, device.name)">
                {{ editableDevices[device.device_id].editing ? 'Submit' : 'Edit' }}
              </button>
              <button class="button is-small is-dark top-buffer-small" 
              v-if="this.editableDevices[device.device_id].editing === true" @click="stopEdit(device.device_id)">Cancel</button>
              <button class="button is-danger is-small is-dark top-buffer-small" 
              v-if="this.editableDevices[device.device_id].editing === true" @click="deleteDevice(device.device_id)">Delete</button>
            </td>
          </tr>
        </tbody>


      </table>
      <p v-if="error" class="error">{{ error }}</p>
    </div>
  </div>
</template>

<script>
import UserRegister from '../components/UserRegister.vue';
import { mapState, mapActions } from 'vuex';

export default {
  components: {
    UserRegister
  },
  data() {
    return {
      editableDevices: {},
      showModal: false,
      orgDeviceName: '',
    };
  },
  computed: {
    ...mapState(['devices', 'orgDevices', 'error', 'user', 'displayname', 'permissions', 'publicInfo']),
  },
  created() {
    if (this.$store.getters.isAuthenticated) {
      this.fetchDevices().then(() => {
        this.initializeEditables();
      });
      this.fetchDevicesOrg()
    } else {
      console.log("OUT")
      this.$router.push('/');
    }
  },
  methods: {
    ...mapActions([
      'fetchDevices',
      'fetchDevicesOrg',
      'logout',
      'updateDevice',
      'reScan',
      'removeDevice'
    ]),
    async reScanExisting() {
      try {
        const request = await this.reScan();
        if (request === 200) {
          location.reload();
        }
        else {
          alert("Something went wrong, contact admin.")
        }
      } catch (err) {
        console.log("Something went wrong");
      }
    },
    async userLogout() {
      try {
        this.logout();
        this.$router.push('/');
      } catch (err) {
        console.log("Something went wrong");
      }
    },
    initializeEditables() {
      this.editableDevices = {};
      this.devices.forEach(device => {
        this.editableDevices[device.device_id] = {
          description: device.description,
          extra: device.extra,
          deviceName: device.name,
          type: device.type,
          editing: false
        };
      });
    },

    stopEdit(id) {
      this.editableDevices[id].editing = false
    },

    async deleteDevice(deviceId) {
      this.stopEdit(deviceId)
      try {
        if (confirm(`Are you sure you want to delete this device?`)) {
                console.log(deviceId)
                await this.removeDevice(deviceId);
                this.fetchDevices().then(() => {
                  this.initializeEditables();
                });
                this.fetchDevicesOrg()
            }
      } catch (err) {
        console.log("Something went wrong");
      }
    },

    async toggleEdit(deviceId, oDeviceName) {
      const deviceState = this.editableDevices[deviceId];
      console.log(deviceState)
      if (deviceState.editing) {        
        try {
          console.log(oDeviceName, deviceState.type)
          await this.updateDevice({
            deviceId,
            description: deviceState.description,
            extra: deviceState.extra,
            type: deviceState.type,
            deviceName: deviceState.deviceName,
            orgCleanDeviceName: oDeviceName,
          });
          alert('Device updated!');
        } catch (err) {
          console.log('Update failed',(err));
        }
      }
      deviceState.editing = !deviceState.editing;
    },
    formatExtra(extra) {
      try {
      const obj = JSON.parse(extra);
      let output = '';
      // So ugly, try and fix.
      for (const key in obj) {
        output += `${key}:\n`;
        obj[key].forEach(entry => {
          for (const subkey in entry) {
            output += `${subkey}: ${entry[subkey]}\n`;
          }
        });
      }
      return output.trim();
    } catch (e) {
      return extra || '';
    }
  }
  }
};

</script>

<style scoped>
pre {
  font-family: inherit;
  padding: 0px;
  background-color: inherit;
  overflow-x: auto;
}
.container {
  max-width: 1600px;
}
.top-buffer {
  margin-top: 25px;
}
.top-buffer-small {
  margin-top: 15px;
}
.stick-right {
  float:right;
}
.t-aligne {
  margin-left: 30px;
}
.smaller-font {
  font-size: smaller;
}

.extra input-height {
  height: auto;
}

table {
  width: 90%;
  border-collapse: collapse;
  margin-left: 5%;
}

th,
td {
  padding: 8px;
  border: 1px solid #ddd;
}

th {
  background-color: #414141;
  color: white;
  font-size: 12px;
}

.error {
  color: red;
}
</style>