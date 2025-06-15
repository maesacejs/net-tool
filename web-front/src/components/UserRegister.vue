<template>
    <div>
        <div class="tabs is-toggle is-fullwidth is-small">
            <ul>
                <li :class="{ 'is-active': activeTab === 'register' }">
                    <a @click="activeTab = 'register'">Register New User</a>
                </li>
                <li :class="{ 'is-active': activeTab === 'manage' }">
                    <a @click="activeTab = 'manage'">Manage Users</a>
                </li>
            </ul>
        </div>
        <div v-if="activeTab === 'register'" class="columns">
            <div class="column">
                <form class="box bit-smaler" @submit.prevent="submitRegistration()">
                    <div class="field danger">*Note: All inputs are required</div>
                    <div class="field">
                        <label for="username">Username:</label>
                        <div class="control">
                            <input type="text" v-model="username" id="username" required />
                        </div>
                    </div>
                    <div class="field">
                        <label for="firstname">First name:</label>
                        <div class="control">
                            <input type="text" v-model="firstname" id="firstname" required />
                        </div>
                    </div>
                    <div class="field">
                        <label for="lastname">Last name:</label>
                        <div class="control">
                            <input type="text" v-model="lastname" id="lastname" required />
                        </div>
                    </div>
                    <div class="field">
                        <label for="emailAddress">Email address:</label>
                        <div class="control">
                            <input type="email" v-model="emailAddress" id="emailAddress" required />
                        </div>
                    </div>
                    <div class="field">
                        <label for="password">Password:</label>
                        <div class="control">
                            <input type="password" v-model="password" id="password" required />
                        </div>
                    </div>
                    <div class="field">
                        <label>User permissions:</label>
                        <div class="control">
                            <div class="checkbox-group">
                                <label>
                                    <input type="checkbox" v-model="userPermissions.reading" id="reading" />
                                    Reading
                                </label>
                                <label>
                                    <input type="checkbox" v-model="userPermissions.admin_users" id="admin_users" />
                                    Admin
                                </label>
                                <label>
                                    <input type="checkbox" v-model="userPermissions.modifying" id="modifying" />
                                    Modifying
                                </label>
                            </div>
                        </div>
                    </div>
                    <button class="button is-primary is-small">Submit</button>
                    <p v-if="error" class="error top-buffer">{{ error }}</p>
                    <p v-if="regSuccess" class=" box top-buffer is-success">User successfully registred!</p>
                </form>
            </div>
        </div>

        <div v-if="activeTab === 'manage'" class="box">
            <div v-for="user in users" :key="user.user_id" class="box">
                <p> Firstname:
                    <span v-if="editedUserId !== user.user_id">{{ user.firstname }}</span>
                    <input v-else type="text" v-model="user.firstname" class="input is-small" />
                </p>
                <p>Lastname:
                    <span v-if="editedUserId !== user.user_id">{{ user.lastname }}</span>
                    <input v-else type="text" v-model="user.lastname" class="input is-small" />
                </p>
                <p>Username:
                    <span v-if="editedUserId !== user.user_id"><b>{{ user.username }}</b></span>
                    <input v-else type="text" v-model="user.username" class="input is-small" />
                </p>
                <p>Email address:
                    <span v-if="editedUserId !== user.user_id">{{ user.email }}</span>
                    <input v-else type="email" v-model="user.email" class="input is-small" />
                </p>
                <span v-if="editedUserId !== user.user_id">
                    Reading: {{ user.reading }} /
                    Modifying: {{ user.modifying }} /
                    User admin: {{ user.admin_users }}
                </span>
                <div v-else>
                    <div>
                        Current:
                        Reading: {{ user.reading }} /
                        Modifying: {{ user.modifying }} /
                        User admin: {{ user.admin_users }}
                    </div>
                    </br>
                    <div class="field is-grouped is-grouped-multiline">
                        <label class="checkbox">
                            <input type="checkbox" v-model="user.reading" :disabled="editedUserId !== user.user_id" />
                            Reading
                        </label>
                        <label class="checkbox">
                            <input type="checkbox" v-model="user.modifying" :disabled="editedUserId !== user.user_id" />
                            Modifying
                        </label>
                        <label class="checkbox">
                            <input type="checkbox" v-model="user.admin_users"
                                :disabled="editedUserId !== user.user_id" />
                            Admin
                        </label>
                    </div>
                </div>
                <div v-if="editedUserId === user.user_id" class="columns">
                    <div class="column is-6">
                        <p>New password:</p>
                        <p>Repeat new password:</p>
                    </div>
                    <div class="column">
                        <input type="password" v-if="editedUserId === user.user_id" v-model="passwordChange.new_pwd" />
                        <input type="password" v-if="editedUserId === user.user_id" v-model="passwordChangeCheck" />
                    </div>
                </div>
                <div class="buttons top-buffer-small">
                    <button class="button is-primary is-small" v-if="editedUserId === user.user_id"
                        @click="saveUser(user)">
                        Save
                    </button>
                    <button class="button is-light is-small" v-if="editedUserId === user.user_id" @click="cancelEdit">
                        Cancel
                    </button>
                    <button class="button is-dark is-small" v-else @click="editUser(user)">
                        Edit
                    </button>
                    <button class="button is-warning is-dark is-small left-bump" v-if="editedUserId === user.user_id"
                        @click="changePassword(user)">
                        Change password
                    </button>
                    <button class="button is-danger is-dark is-small left-bump" @click="deleteUser(user)">
                        Delete
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>


<script>
import { mapState, mapActions } from 'vuex';

export default {
    name: 'UserRegister',
    data() {
        return {
            activeTab: 'register',
            username: '',
            firstname: '',
            lastname: '',
            emailAddress: '',
            password: '',
            userPermissions: {
                reading: false,
                admin_users: false,
                modifying: false,
            },
            regSuccess: false,
            users: [],
            editedUserId: null,
            originalUserData: null,
            passwordChangeCheck: '',
            passwordChange: {
                "new_pwd": ''
            }
        };
    },
    computed: {
        ...mapState(['error']),
    },
    methods: {
        ...mapActions(['register', 'fetchUsers', 'updateUser', 'removeUser', 'updateUserPassword']),

        async submitRegistration() {
            const userData = {
                "username": this.username,
                "firstname": this.firstname,
                "lastname": this.lastname,
                "email": this.emailAddress,
                "permissions": this.userPermissions,
                "password": this.password
            }
            try {
                const req = await this.register(userData)
                if (req === true) {
                    console.log("Success")
                    this.regSuccess = true;
                    this.username = '';
                    this.firstname = '';
                    this.lastname = '';
                    this.emailAddress = '';
                    this.userPermissions.reading = false;
                    this.userPermissions.admin_users = false;
                    this.userPermissions.modifying = false;
                    this.password = ''
                    setTimeout(() => this.regSuccess = false, 5000);
                }
            } catch (err) {
                console.log(err)
                console.log("Error but not from API")
            }
        },
        async loadUsers() {
            this.users = await this.fetchUsers();
        },

        editUser(user) {
            this.editedUserId = user.user_id;
            this.originalUserData = JSON.parse(JSON.stringify(user));
        },

        okPassword(pwd) {
            const up = /[A-Z]/.test(pwd);
            const low = /[a-z]/.test(pwd);
            const num = /[0-9]/.test(pwd);
            const spch = /[^A-Za-z0-9]/.test(pwd);

            if (up && low && num && spch) {
                return true;
            }

        },

        checkPassword() {
            if (this.passwordChange.new_pwd && this.passwordChangeCheck) {
                if (this.passwordChange.new_pwd != this.passwordChangeCheck) {
                    alert('Passwords don\'t match');
                    return false
                }
                if (this.okPassword(this.passwordChange.new_pwd) != true) {
                    alert('Need uppercase, lowercase, numbers and special character')
                    return false
                }
                if (this.passwordChange.length < 12) {
                    alert('Needs to be more than 12 characters long')
                    return false
                }

                return true
            }
            else
                alert('No password submitted')

        },

        async changePassword(user) {
            if (this.checkPassword() === true) {
                console.log(user.user_id)
                console.log("made it!")
                try {
                    console.log(this.passwordChange.new_pwd)
                    const new_password = {
                        "new_pwd": this.passwordChange.new_pwd,
                        "user_id": user.user_id
                    };
                    await this.updateUserPassword(new_password);
                }
                catch (err) {
                    console.log(err)
                }
                this.cancelEdit()
                this.passwordChange.new_pwd = '';
                alert('Password is updated!')
            }


        },

        async saveUser(user) {
            const userUpdates = {
                "user_id": user.user_id,
                "firstname": user.firstname,
                "lastname": user.lastname,
                "username": user.username,
                "email": user.email,
                "permissions": {
                    "reading": user.reading,
                    "modifying": user.modifying,
                    "admin_users": user.admin_users
                }
            };
            try {
                await this.updateUser(userUpdates);
                this.editedUserId = null;
            }
            catch (err) {
                console.log(err)
                console.log("Error, check API or database")
            }

        },

        cancelEdit() {
            const idx = this.users.findIndex(u => u.user_id === this.editedUserId);
            // Putting back originale user data. 
            if (idx !== -1) {
                this.users.splice(idx, 1, this.originalUserData);
            }
            this.editedUserId = null;
            this.originalUserData = null;
            this.passwordChange = '';
            this.passwordChangeCheck = '';
        },

        async deleteUser(user) {
            if (confirm(`Are you sure you want to delete ${user.username}?`)) {
                console.log(user.user_id)
                await this.removeUser(user.user_id);
                this.loadUsers();
            }
        }
    },
    mounted() {
        this.loadUsers();
    }
}

</script>

<style scoped>
.danger {
    color: red;
}

.left-bump {
    margin-left: 7px;
}

.is-success {
    color: green;
}

.top-buffer {
    margin-top: 25px;
}

.top-buffer-small {
    margin-top: 5px;
}
</style>