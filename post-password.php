<?php
/*
* Plugin Name: Post Password
* Plugin URI:  https://creativep.pl/
* Description: Password protect comments on posts, pages, and WooCommerce reviews. Collect and display incorrect password attempts. Block IPs after exceeding incorrect password attempts.
* Version: 1.6.1
* Author: CREATIVEP Dawid Boho - CREATIVEP.PL
* Author URI:  https://dboho.pl/
* License:     GPLv2 or later
* License URI: http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
* This program is free software; you can redistribute it and/or modify it under the terms of the GNU
* General Public License version 2, as published by the Free Software Foundation. You may NOT assume
* that you can use any other version of the GPL.
*
* This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
* even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

if (!defined('ABSPATH')) {
    exit; 
}

class PostPasswordPlugin {
    private $password_option_name = 'post_password_comment';
    private $message_option_name = 'post_password_message';
    private $admin_option_name = 'post_password_admin';
    private $woocommerce_option_name = 'post_password_woocommerce';
    private $log_attempts_option_name = 'post_password_log_attempts';
    private $block_ip_option_name = 'post_password_block_ip';
    private $block_duration_option_name = 'post_password_block_duration';
    private $max_attempts_option_name = 'post_password_max_attempts';
    private $log_table_name;
    private $blocked_ips_table_name;

    public function __construct() {
        global $wpdb;
        $this->log_table_name = $wpdb->prefix . 'post_password_log';
        $this->blocked_ips_table_name = $wpdb->prefix . 'post_password_blocked_ips';

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'settings_init'));
        add_action('admin_init', array($this, 'handle_unblock_ip'));
        add_action('comment_form', array($this, 'add_password_field'));
        add_filter('preprocess_comment', array($this, 'check_comment_password'));
        add_action('woocommerce_after_review_form', array($this, 'add_password_field_to_woocommerce'));
        add_filter('preprocess_comment', array($this, 'check_woocommerce_review_password'));
        add_action('wp', array($this, 'schedule_cleanup'));
        add_action('post_password_cleanup', array($this, 'cleanup_logs'));

        register_activation_hook(__FILE__, array($this, 'plugin_activation'));
        register_deactivation_hook(__FILE__, array($this, 'plugin_deactivation'));
    }

    public function add_admin_menu() {
        add_options_page(
            'Post Password Settings',
            'Post Password',
            'manage_options',
            'post-password',
            array($this, 'options_page')
        );
    }

    public function settings_init() {
        register_setting('postPasswordPage', $this->password_option_name);
        register_setting('postPasswordPage', $this->message_option_name);
        register_setting('postPasswordPage', $this->admin_option_name);
        register_setting('postPasswordPage', $this->woocommerce_option_name);
        register_setting('postPasswordPage', $this->log_attempts_option_name);
        register_setting('postPasswordPage', $this->block_ip_option_name);
        register_setting('postPasswordPage', $this->block_duration_option_name);
        register_setting('postPasswordPage', $this->max_attempts_option_name);

        add_settings_section(
            'postPasswordPage_section',
            __('Set Password for Comments', 'wordpress'),
            array($this, 'settings_section_callback'),
            'postPasswordPage'
        );

        add_settings_field(
            $this->password_option_name,
            __('Password', 'wordpress'),
            array($this, 'settings_field_render'),
            'postPasswordPage',
            'postPasswordPage_section'
        );

        add_settings_field(
            $this->message_option_name,
            __('Password Prompt Message', 'wordpress'),
            array($this, 'message_field_render'),
            'postPasswordPage',
            'postPasswordPage_section'
        );

        add_settings_field(
            $this->admin_option_name,
            __('Require Password for Admin', 'wordpress'),
            array($this, 'admin_field_render'),
            'postPasswordPage',
            'postPasswordPage_section'
        );

        add_settings_field(
            $this->woocommerce_option_name,
            __('Require Password for WooCommerce Reviews', 'wordpress'),
            array($this, 'woocommerce_field_render'),
            'postPasswordPage',
            'postPasswordPage_section'
        );

        add_settings_field(
            $this->log_attempts_option_name,
            __('Log Incorrect Password Attempts', 'wordpress'),
            array($this, 'log_attempts_field_render'),
            'postPasswordPage',
            'postPasswordPage_section'
        );

        add_settings_field(
            $this->block_ip_option_name,
            __('Block IP after failed attempts', 'wordpress'),
            array($this, 'block_ip_field_render'),
            'postPasswordPage',
            'postPasswordPage_section'
        );

        add_settings_field(
            $this->max_attempts_option_name,
            __('Number of attempts before blocking IP', 'wordpress'),
            array($this, 'max_attempts_field_render'),
            'postPasswordPage',
            'postPasswordPage_section'
        );

        add_settings_field(
            $this->block_duration_option_name,
            __('Block duration (in days)', 'wordpress'),
            array($this, 'block_duration_field_render'),
            'postPasswordPage',
            'postPasswordPage_section'
        );
    }

    public function settings_field_render() {
        $value = get_option($this->password_option_name);
        echo '<input type="text" name="' . $this->password_option_name . '" value="' . esc_attr($value) . '">';
    }

    public function message_field_render() {
        $value = get_option($this->message_option_name, 'Enter Secret Password');
        echo '<input type="text" name="' . $this->message_option_name . '" value="' . esc_attr($value) . '">';
    }

    public function admin_field_render() {
        $value = get_option($this->admin_option_name, 'no');
        echo '<input type="checkbox" name="' . $this->admin_option_name . '" value="yes" ' . checked($value, 'yes', false) . '> ' . __('Require password for administrators', 'wordpress');
    }

    public function woocommerce_field_render() {
        $value = get_option($this->woocommerce_option_name, 'no');
        echo '<input type="checkbox" name="' . $this->woocommerce_option_name . '" value="yes" ' . checked($value, 'yes', false) . '> ' . __('Require password for WooCommerce reviews', 'wordpress');
    }

    public function log_attempts_field_render() {
        $value = get_option($this->log_attempts_option_name, 'no');
        echo '<input type="checkbox" name="' . $this->log_attempts_option_name . '" value="yes" ' . checked($value, 'yes', false) . '> ' . __('Log incorrect password attempts', 'wordpress');
    }

    public function block_ip_field_render() {
        $value = get_option($this->block_ip_option_name, 'no');
        echo '<input type="checkbox" name="' . $this->block_ip_option_name . '" value="yes" ' . checked($value, 'yes', false) . '> ' . __('Block IP after X failed attempts', 'wordpress');
    }

    public function max_attempts_field_render() {
        $value = get_option($this->max_attempts_option_name, 3);
        echo '<input type="number" name="' . $this->max_attempts_option_name . '" value="' . esc_attr($value) . '">';
    }

    public function block_duration_field_render() {
        $value = get_option($this->block_duration_option_name, 7);
        echo '<input type="number" name="' . $this->block_duration_option_name . '" value="' . esc_attr($value) . '">';
    }

    public function settings_section_callback() {
        echo __('Enter the password that will be required to submit a comment.', 'wordpress');
    }

    public function options_page() {
        ?>
        <div class="wrap">
            <h2>Post Password Settings</h2>
            <form action="options.php" method="post">
                <?php
                settings_fields('postPasswordPage');
                do_settings_sections('postPasswordPage');
                submit_button();
                ?>
            </form>
    
            <?php $this->display_log_attempts(); ?>
            <?php $this->display_blocked_ips(); ?>
    
            <form method="post">
                <?php wp_nonce_field('clear_log_attempts_action', 'clear_log_attempts_nonce'); ?>
                <input type="submit" name="clear_log_attempts" value="Clear All Incorrect Password Attempts" class="button button-secondary">
            </form>
    
            <?php
            if (isset($_POST['clear_log_attempts']) && check_admin_referer('clear_log_attempts_action', 'clear_log_attempts_nonce')) {
                $this->clear_all_log_attempts();
                echo '<div class="notice notice-success"><p>All incorrect password attempts have been cleared.</p></div>';
            }
            ?>
        </div>
        <?php
    }

    public function clear_all_log_attempts() {
        global $wpdb;
        $wpdb->query("TRUNCATE TABLE {$this->log_table_name}");
    }
    
    public function add_password_field() {
        $require_admin = get_option($this->admin_option_name, 'no');

        if ($require_admin !== 'yes' && current_user_can('administrator')) {
            return;
        }

        $message = get_option($this->message_option_name, 'Enter Secret Password');
        ?>
        <p>
            <label for="comment_password"><?php echo esc_html($message); ?> <span class="required">*</span></label><br />
            <input type="text" name="comment_password" id="comment_password" required="required" />
        </p>
        <?php
    }

    public function check_comment_password($commentdata) {
        $password = get_option($this->password_option_name);
        $require_admin = get_option($this->admin_option_name, 'no');
        $log_attempts = get_option($this->log_attempts_option_name, 'no');
        $block_ip = get_option($this->block_ip_option_name, 'no');
        $max_attempts = get_option($this->max_attempts_option_name, 3);
        $block_duration = get_option($this->block_duration_option_name, 7);
        $ip_address = $_SERVER['REMOTE_ADDR'];

        if ($this->is_ip_blocked($ip_address)) {
            wp_die(__('Your IP is blocked due to multiple incorrect password attempts.', 'wordpress'));
        }

        if ($require_admin !== 'yes' && current_user_can('administrator')) {
            return $commentdata;
        }

        if (isset($_POST['comment_password']) && $_POST['comment_password'] === $password) {
            return $commentdata;
        } else {
            if ($log_attempts === 'yes') {
                $this->log_incorrect_attempt($ip_address);

                if ($block_ip === 'yes') {
                    $attempts = $this->get_attempt_count($ip_address);
                    if ($attempts >= $max_attempts) {
                        $this->block_ip($ip_address, $block_duration);
                        wp_die(__('Your IP has been blocked due to multiple incorrect password attempts.', 'wordpress'));
                    }
                }
            }
            wp_die(__('Error: Incorrect password. Your comment could not be submitted.', 'wordpress'));
        }
    }

    public function add_password_field_to_woocommerce() {
        if ('yes' === get_option($this->woocommerce_option_name, 'no')) {
            $this->add_password_field();
        }
    }

    public function check_woocommerce_review_password($commentdata) {
        if ('yes' === get_option($this->woocommerce_option_name, 'no')) {
            return $this->check_comment_password($commentdata);
        }
        return $commentdata;
    }

    public function plugin_activation() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $log_table_sql = "CREATE TABLE IF NOT EXISTS {$this->log_table_name} (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            attempt_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY (id)
        ) $charset_collate;";

        $blocked_ips_sql = "CREATE TABLE IF NOT EXISTS {$this->blocked_ips_table_name} (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            blocked_until datetime NOT NULL,
            PRIMARY KEY (id)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($log_table_sql);
        dbDelta($blocked_ips_sql);

        // Check table if exist - DODAŁEM
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$this->log_table_name}'") === $this->log_table_name;
    
        if (!$table_exists) {
            error_log("Table {$this->log_table_name} does not exist after attempting to create it.");
        } else {
            error_log("Table {$this->log_table_name} was created successfully.");
        }

        // Check table if exist - DODAŁEM
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$this->blocked_ips_table_name}'") === $this->blocked_ips_table_name;
    
        if (!$table_exists) {
            error_log("Table {$this->blocked_ips_table_name} does not exist after attempting to create it.");
        } else {
            error_log("Table {$this->blocked_ips_table_name} was created successfully.");
        }

        if (!wp_next_scheduled('post_password_cleanup')) {
            wp_schedule_event(time(), 'daily', 'post_password_cleanup');
        }
    }

    public function plugin_deactivation() {
        global $wpdb;

        wp_clear_scheduled_hook('post_password_cleanup');

        $wpdb->query("DROP TABLE IF EXISTS {$this->blocked_ips_table_name}");
        $wpdb->query("DROP TABLE IF EXISTS {$this->log_table_name}");
    
        delete_option($this->password_option_name);
        delete_option($this->message_option_name);
        delete_option($this->admin_option_name);
        delete_option($this->woocommerce_option_name);
        delete_option($this->log_attempts_option_name);
        delete_option($this->block_ip_option_name);
        delete_option($this->block_duration_option_name);
        delete_option($this->max_attempts_option_name);
    }

    public function schedule_cleanup() {
        if (!wp_next_scheduled('post_password_cleanup')) {
            wp_schedule_event(time(), 'daily', 'post_password_cleanup');
        }
    }

    public function cleanup_logs() {
        global $wpdb;
        $wpdb->query("DELETE FROM {$this->log_table_name} WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 7 DAY)");
    }

    public function log_incorrect_attempt($ip_address) {
        global $wpdb;
        $wpdb->insert(
            $this->log_table_name,
            array('ip_address' => $ip_address),
            array('%s')
        );
    }

    public function get_attempt_count($ip_address) {
        global $wpdb;
        return $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->log_table_name} WHERE ip_address = %s AND attempt_time >= DATE_SUB(NOW(), INTERVAL 1 DAY)",
            $ip_address
        ));
    }

    public function block_ip($ip_address, $duration) {
        global $wpdb;
        $blocked_until = date('Y-m-d H:i:s', strtotime("+$duration days"));
        $wpdb->insert(
            $this->blocked_ips_table_name,
            array(
                'ip_address' => $ip_address,
                'blocked_until' => $blocked_until
            ),
            array(
                '%s',
                '%s'
            )
        );
    }

    public function is_ip_blocked($ip_address) {
        global $wpdb;
        return $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->blocked_ips_table_name} WHERE ip_address = %s AND blocked_until > NOW()",
            $ip_address
        )) > 0;
    }

    public function display_log_attempts() {
        global $wpdb;
        $log_attempts = get_option($this->log_attempts_option_name, 'no');
    
        if ($log_attempts === 'yes') {

            $results = $wpdb->get_results(
                "SELECT ip_address, COUNT(*) as attempt_count 
                 FROM $this->log_table_name 
                 GROUP BY ip_address 
                 ORDER BY attempt_count DESC"
            );
    
            echo '<h2>Incorrect Password Attempts</h2>';
            echo '<table>';
            echo '<thead><tr><th>IP Address</th><th>Number of Attempts</th></tr></thead>';
            echo '<tbody>';
            foreach ($results as $row) {
                echo '<tr>';
                echo '<td>' . esc_html($row->ip_address) . '</td>';
                echo '<td>' . esc_html($row->attempt_count) . '</td>';
                echo '</tr>';
            }
            echo '</tbody>';
            echo '</table>';
        }
    }

    public function display_blocked_ips() {
        global $wpdb;
        $results = $wpdb->get_results("SELECT ip_address, blocked_until FROM {$this->blocked_ips_table_name}");

        echo '<h2>' . __('Blocked IP Addresses', 'wordpress') . '</h2>';
        echo '<table>';
        echo '<tr><th>' . __('IP Address', 'wordpress') . '</th><th>' . __('Blocked Until', 'wordpress') . '</th><th>' . __('Actions', 'wordpress') . '</th></tr>';
        foreach ($results as $row) {
            echo '<tr><td>' . esc_html($row->ip_address) . '</td><td>' . esc_html($row->blocked_until) . '</td><td>';
            echo '<a href="' . esc_url(add_query_arg(array('page' => 'post-password', 'unblock_ip' => esc_attr($row->ip_address), 'unblock_ip_nonce' => wp_create_nonce('unblock_ip_nonce')), admin_url('options-general.php'))) . '">' . __('Unblock', 'wordpress') . '</a>';
            echo '</td></tr>';
        }
        echo '</table>';
    }

    public function handle_unblock_ip() {
        if (isset($_GET['unblock_ip']) && isset($_GET['unblock_ip_nonce'])) {
            
            if (!wp_verify_nonce($_GET['unblock_ip_nonce'], 'unblock_ip_nonce')) {
                wp_die(__('Security check failed', 'wordpress'));
            }

            if (!current_user_can('manage_options')) {
                wp_die(__('You do not have sufficient permissions to access this page.', 'wordpress'));
            }

            global $wpdb;
            $ip_address = sanitize_text_field($_GET['unblock_ip']);
            $wpdb->delete($this->blocked_ips_table_name, array('ip_address' => $ip_address));

            wp_redirect(admin_url('options-general.php?page=post-password'));
            exit;
        }
    }
}
new PostPasswordPlugin();
?>